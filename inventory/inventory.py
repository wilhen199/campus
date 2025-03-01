import concurrent.futures as cf
import threading
import pandas as pd
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
import devices as dev
from rich.pretty import pprint
import re
import time

# Iniciar el tiempo de ejecución
start_time = time.time()

# Leer los datos del archivo xlsx usando pandas
df = pd.read_excel('./Files/inventory.xlsx','Hoja1')

# Datos comunes de conexión para netmiko (ajustar según sea necesario)
device_params = dev.cisco_ssh
#device_params = dev.cisco_telnet

def clean_text(text):
    """Elimina caracteres no imprimibles de un string."""
    return re.sub(r'[\x00-\x1F\x7F]', '', str(text))  # Remueve caracteres ASCII no imprimibles

# Guardar resultados
def save_results(results, output_file):
    header = ['ip_address', 'expected_hostname','result_script' ,'prompt', 'modelo', 'serial', 'software', 'existing_users', 'snmp', 'tacacs_source']
    
    data = []
    for result in results:
        fields = result.split(';', 9)
        cleaned_fields = [clean_text(field) for field in fields]  # Aplica la limpieza
        data.append(cleaned_fields)

        #data.append(fields)


    df = pd.DataFrame(data, columns=header)
    df.to_excel(output_file, index=False)
    pprint(f'Resultados guardados en {output_file}')

# Función para conectarse a un dispositivo
def connect_device(device_params, ip_address):
    device_params_local = device_params.copy()
    device_params_local['host'] = ip_address
    device_params_local['session_log'] = f"./session_logs/{ip_address}.log"
    return ConnectHandler(**device_params_local)

# Función genérica de manejo de errores
def handle_exceptions(ip_address, expected_hostname, err):
    error_map = {
        NetMikoTimeoutException: "Error: Timeout",
        NetMikoAuthenticationException: "Error: Authentication failed",
        SSHException: "Error: SSH connection failed"
    }
    error_msg = error_map.get(type(err), f"Error: General {err}")
    pprint(f"{ip_address} - {error_msg}")
    return f"{ip_address};{expected_hostname};{error_msg};"

# Función para gestionar equipos en Cisco
def manage_cisco(net_connect, ip_address, expected_hostname):
    current_prompt = net_connect.find_prompt()
    device_info = net_connect.send_command("show version", expect_string=current_prompt, read_timeout=180)

    # Obtener modelo, serial y SO del dispositivo
    if "Cisco Nexus" in device_info: # Si el dispositivo es Cisco Nexus, ejecuta este bloque
        modelo = re.search(r'Hardware\s+(.*)',device_info, re.IGNORECASE).group(1)
        serial = re.search(r'VDH=+(.*)', net_connect.send_command("show license host-id", expect_string=current_prompt, read_timeout=180)).group(1)
        software = re.search(r'System version+(.*)', device_info).group()    
    else: # Si no es Cisco Nexus, ejecuta este bloque
        modelo = re.search(r'Model [N-n]umber+(\W)+(.*)', device_info).group(2)
        serial = re.findall(r'System [S-s]erial [N-n]umber\s+:\s+(\S+)', device_info)
        software = re.search(r'(Version)+(.*)', device_info).group()
    
    # Obtener usuarios locales creados
    usernames = net_connect.send_command("show running-config | include username")
    existing_users = [line.split()[1] for line in usernames.splitlines() if line.startswith('username')]

    # Obtener SNMP Community
    snmp = net_connect.send_command('show running-config | include community', expect_string=current_prompt, read_timeout=180)
    
    # Obtener ip tacacs source-interface
    tacacs = net_connect.send_command("show running-config | section aaa", expect_string=current_prompt, read_timeout=180)
    tacacs_match = re.search(r'ip tacacs source-interface\s+(.*)', tacacs) if tacacs else None
    tacacs_source = tacacs_match.group(1).strip() if tacacs_match else "No encontrado ip tacacs source-interface en módulo aaa"
    result_script= "OK"

    #return f"{ip_address},{expected_hostname},{current_prompt},{modelo},{serial},{software},{existing_users},{snmp},{tacacs_source}"
    return f"{ip_address};{expected_hostname};{result_script};{current_prompt};{modelo};{serial};{software};{existing_users};{snmp};{tacacs_source}"


# Función para gestionar equipos Extreme
def manage_extreme(net_connect, ip_address, expected_hostname):
    current_prompt = net_connect.find_prompt()

    # Obtener modelo, serial y SO del dispositivo
    device_info = net_connect.send_command("show switch", expect_string=current_prompt, read_timeout=180)
    current_prompt = net_connect.find_prompt()
    device_serial = net_connect.send_command("show version", expect_string=current_prompt, read_timeout=180)
    current_prompt = net_connect.find_prompt()
    modelo = re.search(r'System Type:\s+(.*)', device_info, re.IGNORECASE).group(1)
    serial = re.search(r'Switch\s+(.:)+\s+(.*)', device_serial, re.IGNORECASE).group(2)
    software = re.search(r'Primary ver:\s+(.*)', device_info, re.IGNORECASE).group(1)

    # Obtener usuarios locales creados
    usernames = net_connect.send_command("show accounts")
    existing_users = re.findall(r'^\s+([a-zA-Z0-9]+)', usernames, re.MULTILINE)[1:]

    # Obtener SNMP Community
    snmp = net_connect.send_command('show configuration | include community', expect_string=current_prompt, read_timeout=180)

    tacacs_source = "N/A"
    result_script= "OK"
    #return f"{ip_address},{expected_hostname},{current_prompt},{modelo},{serial},{software},{existing_users},{snmp},{tacacs_source}"
    return f"{ip_address};{expected_hostname};{result_script};{current_prompt};{modelo};{serial};{software};{existing_users};{snmp};{tacacs_source}"

# Función para gestionar equipos Huawei
def manage_huawei(net_connect, ip_address, expected_hostname):
    current_prompt = net_connect.find_prompt()

    # Obtener modelo, serial y SO del dispositivo
    device_info = net_connect.send_command("display version", expect_string=current_prompt, read_timeout=180)
    device_serial = net_connect.send_command("display device esn", expect_string=current_prompt, read_timeout=180)
    modelo = (re.findall(r'Type\s+\W+(.*)', device_info))
    software = re.search(r'Version\s(.*)', device_info).group(1)
    serial = re.findall(r'slot\s+[0-9]+[:]+\s+(.*)', device_serial)

    # Obtener usuarios locales creados
    usernames = net_connect.send_command("display current-configuration | include local-user")
    existing_users = set(re.findall(r' local-user (?!policy)(\S+)', usernames))

    snmp = "N/A"
    tacacs_source = "N/A"
    result_script= "OK"
    #return f"{ip_address},{expected_hostname},{current_prompt},{modelo},{serial},{software},{existing_users},{snmp},{tacacs_source}"
    return f"{ip_address};{expected_hostname};{result_script};{current_prompt};{modelo};{serial};{software};{existing_users};{snmp};{tacacs_source}"


BRAND_FUNCTIONS = {
    'Cisco': (dev.cisco_ssh, manage_cisco),
    'Extreme': (dev.extreme_ssh, manage_extreme),
    'Huawei': (dev.huawei_ssh, manage_huawei)
}

results = []
results_lock = threading.Lock()

def verify_device(row):
    ip_address = row['ip_address']
    expected_hostname = row.get('expected_hostname')
    brand = row.get('brand')

    if brand not in BRAND_FUNCTIONS:
        result = f"{ip_address},{expected_hostname},,Error: Marca desconocida"
        with results_lock:
            results.append(result)
        return

    device_params, manage_function = BRAND_FUNCTIONS[brand]
    
    # Inicializar result como un diccionario vacío antes de intentar cualquier operación
    result = {
        'ip_address': ip_address,
        'expected_hostname': expected_hostname,
        "result_script": "OK",
        'prompt': '',
        'modelo': '',
        'serial': '',
        'software': '',
        'existing_users': '',
        'snmp': '',
        'tacacs_source': ''}

    try:
        with connect_device(device_params, ip_address) as net_connect:
            result = manage_function(net_connect, ip_address, expected_hostname)
            pprint(result)
    except Exception as err:
        result = handle_exceptions(ip_address, expected_hostname, err)
    
    with results_lock:
        results.append(result)

# Ejecutar en múltiples hilos
with cf.ThreadPoolExecutor() as executor:
    futures = [executor.submit(verify_device, row) for _, row in df.iterrows()]
    for future in cf.as_completed(futures):
        future.result()

# Guardar resultados
inventory_output = './Results/ex_inventory_results.xlsx'
save_results(results, inventory_output)

# Calcular y mostrar el tiempo total de ejecución
end_time = time.time()
elapsed_time = (end_time - start_time) / 60
pprint(f'Tiempo total de ejecución: {elapsed_time:.2f} minutos')