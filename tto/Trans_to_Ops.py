import concurrent.futures as cf
import threading
import pandas as pd
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
import devices as dev
from rich.pretty import pprint
import re


# Leer los datos del archivo xlsx usando pandas
df = pd.read_excel('./Files/TTO.xlsx','Hoja1')

# Guardar el DataFrame en un archivo Excel
output_file = './Results/TTO_results.xlsx'

# Datos comunes de conexión para netmiko (ajustar según sea necesario)
device_params = dev.cisco_ssh
#device_params = dev.cisco_telnet

# Lista para almacenar los resultados
results = []
results_lock = threading.Lock()

def verify_device(row):
    ip_address = row['ip_address']
    expected_hostname = row.get('expected_hostname')  # Obtener el nombre del host esperado si está disponible
    jira = row['jira'] # Obtener el id del proyecto en jira
    project_description = row['project_description'] # Obtener la descripción del proyecto
    network = "N/A"
    network_status = "N/A"
    dna = "N/A"
    dna_status = "N/A"
    
    # Actualizar los parámetros del dispositivo con la IP actual
    device_params_local = device_params.copy()
    device_params_local['host'] = ip_address

    # Guardar logs ssh
    output_logs = f"./session_logs/{ip_address}.log"
    device_params_local['session_log'] = output_logs

    # Inicializar result como un diccionario vacío antes de intentar cualquier operación
    result = {
        "ip_address": ip_address,
        "expected_hostname": expected_hostname,
        "jira": jira,
        "project_description": project_description,
        "result_script": "OK",
        "modelo": "N/A",
        "serial": "N/A",
        "software": "N/A",
        "time": "N/A",
        "users": [],
        "loopback": "N/A",
        "interface_mpls": [],
        "int_description": [],
        "tacacs_source": "",
        "snmp_community": "N/A",
        "netconf_status": "N/A",
        "license_network": "N/A",
        "license_dna": "N/A",
        "VLANs": [],}

    pprint(f"Conectando a {ip_address}...")
    try:
        with ConnectHandler(**device_params_local) as net_connect:
            # Entrar al modo enable
            net_connect.enable()
            current_prompt = net_connect.find_prompt()
            
            # Obterner información del dispositivo
            device_info = net_connect.send_command("show version", expect_string=current_prompt, read_timeout=180)

            # Obtener VLANs activas
            vlan_brief = net_connect.send_command("show vlan brief | include active", expect_string=current_prompt, read_timeout=180)
            vlans = []

            # Obterner modelo, serial y SO del dispositivo, VLANs
            if "Cisco Nexus" in device_info: # Si el dispositivo es Cisco Nexus, ejecuta este bloque
                modelo = re.search(r'Hardware\s+(.*)',device_info, re.IGNORECASE).group(1)
                serial = re.search(r'VDH=+(.*)', net_connect.send_command("show license host-id", expect_string=current_prompt, read_timeout=180)).group(1)
                software = re.search(r'System version+(.*)', device_info).group()
                for line in vlan_brief.splitlines():
                    if line.strip() and any(keyword in line for keyword in ['Ports', 'active', '----']):
                        vlan_data = line.split()
                        if len(vlan_data) >= 2:  # Verifica que haya al menos dos elementos (ID y nombre)
                            vlan_id = vlan_data[0]
                            vlan_name = vlan_data[1]
                            vlans.append([vlan_id, vlan_name])
            else: # Si no es Cisco Nexus, ejecuta este bloque
                modelo = re.search(r'Model [N-n]umber+(\W)+(.*)', device_info).group(2)
                serial = re.findall(r'System [S-s]erial [N-n]umber\s+:\s+(\S+)', device_info)
                software = re.search(r'(Version)+(.*)', device_info).group()
                for line in vlan_brief.splitlines():
                    if line.strip() and not line.startswith('VLAN'):
                        vlan_data = line.split()
                        vlan_id = vlan_data[0]
                        vlan_name = vlan_data[1]
                        vlans.append([vlan_id, vlan_name])
            vlans_active = pd.DataFrame(vlans, columns=['ID', 'NAME']).to_string(index=False)

            # Obtener usuarios locales creados
            usernames = net_connect.send_command("show running-config | include username", expect_string=current_prompt, read_timeout=180)
            existing_users = []
            for line in usernames.splitlines():
                if line.startswith('username'):
                    user = line.split()[1]
                    existing_users.append(user)

            # Obtener SNMP Community
            snmp = net_connect.send_command('show running-config | include community', expect_string=current_prompt, read_timeout=180)

            # Obtener licenciamiento del dispositivo
            if "Cisco IOS XE" in device_info or "license" in device_info.lower(): # Si el dispositivo es Cisco XE ejecuta este bloque o si la palabra "license" está al ejecutar show version, ejecuta este bloque
                license = net_connect.send_command("show license usage", expect_string=current_prompt, read_timeout=180).splitlines()
                if len(license) > 18:
                    network = re.search(r'Network[-\s]+(.*)', license[4], re.IGNORECASE).group(0)
                    network_status = re.search(r'Status+(.*)', license[7], re.IGNORECASE).group(0)
                    dna = re.search(r'dna[-\s]+(.*)', license[15], re.IGNORECASE).group(0)
                    dna_status = re.search(r'Status+(.*)', license[18], re.IGNORECASE).group(0)
                else:
                    print(f"Salida insuficiente para {ip_address}")
            else: # Si no es Cisco XE o si la palabra "license" no está al ejecutar show version 
                print(f"Comando no soportado en {ip_address}")

            # Obtener verificación de netconf
            netconf = net_connect.send_command('show running-config | include netconf', expect_string=current_prompt, read_timeout=180)

            # Obtener MLPS en descripción
            int_desc_mpls = net_connect.send_command("show inter description | include MPLS", expect_string=current_prompt, read_timeout=180)
            interface_mpls = []
            int_description = []
            for line in int_desc_mpls.splitlines():
                int = line.split()[0]
                mpls = line.split()[3]
                interface_mpls.append(int)
                int_description.append(mpls)

            # Obtener looback en descripción
            int_loopback = net_connect.send_command("show ip interface brief | include Lo", expect_string=current_prompt, read_timeout=180)
            loopback = re.match(r'(\S+)\s+(\d+\.\d+\.\d+\.\d+)', int_loopback)
            if loopback:
                loopback = f"{loopback.group(1)} {loopback.group(2)}"
            else:
                loopback = "Sin Loopback"

            # Obtener ip tacacs source-interface
            tacacs = net_connect.send_command("show running-config | section aaa", expect_string=current_prompt, read_timeout=180)
            tacacs_match = re.search(r'ip tacacs source-interface\s+(.*)', tacacs) if tacacs else None
            tacacs_source = tacacs_match.group(1).strip() if tacacs_match else "No encontrado ip tacacs source-interface en módulo aaa"
            
            # Obtener show ip interface brief
            int_brief = net_connect.send_command("show ip int brief | exc unassigned", expect_string=current_prompt, read_timeout=180)
            ip_int_brief = []
            for line in int_brief.splitlines():
                if line.strip() and not line.startswith('Interface'):
                    int_data = line.split()
                    interface = int_data[0]
                    ip_address_vlan = int_data[1]
                    ip_int_brief.append(f"{interface}   {ip_address_vlan}")

            # Obtener hora del dispositivo
            time = net_connect.send_command("show clock", expect_string=current_prompt, read_timeout=180)

            # Diccionario con los datos a exportar
            result = {
                "ip_address": ip_address,
                "expected_hostname": expected_hostname,
                "prompt": current_prompt,
                "jira": jira,
                "project_description": project_description,
                "result_script": "OK",
                "modelo": modelo,
                "serial": serial,
                "software": software,
                "time": time,
                "users": existing_users,
                "loopback": loopback,
                "interface_mpls": interface_mpls,
                "int_description": int_description,
                "int_brief": ip_int_brief,
                "tacacs_source": tacacs_source,
                "snmp_community": snmp,
                "netconf_status": netconf,
                "license_network": network +" "+ network_status,
                "license_dna": dna + " " + dna_status,
                "VLANs": vlans_active,}    
            
    except NetMikoTimeoutException:
        print(f"Timeout al conectar a {ip_address}")
        result["result_script"] = "Error: Timeout"
    except NetMikoAuthenticationException:
        print(f"Autenticación fallida al conectar a {ip_address}")
        result["result_script"] = "Authentication failed"
    except (SSHException):
        print (f'SSH might not be enabled: {ip_address}')
        result["result_script"] = "SSH connection failed"
    except Exception as err:
        print(f"Error al conectar a {ip_address}: {err}")
        result["result_script"] = f"General {err}"
    with results_lock:
        results.append(result)

# Create a ThreadPoolExecutor to manage threads
with cf.ThreadPoolExecutor() as executor:
    futures = [executor.submit(verify_device, row) for index, row in df.iterrows()]

    # Ensure all threads have completed
    for future in cf.as_completed(futures):
        future.result()

# Crear un DataFrame con los resultados
df = pd.DataFrame(results)

# Guardar el DataFrame en un archivo Excel
df.to_excel(output_file, index=False)
pprint(f'Resultados guardados en {output_file}')