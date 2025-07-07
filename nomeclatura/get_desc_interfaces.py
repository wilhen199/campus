import concurrent.futures as cf
import threading
import pandas as pd
import re
import os
from dotenv import load_dotenv
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
import devices as dev
from rich.pretty import pprint
import time

load_dotenv()

start_time = time.time()

# Lista para almacenar los resultados y su Lock para concurrencia
results = []
results_lock = threading.Lock()

# Leer los datos del archivo Excel
try:
    df = pd.read_excel('./Files/desc_interfaces.xlsx', 'Hoja1')
    if 'vendor' not in df.columns:
        raise ValueError("La columna 'vendor' no se encontró en el archivo Excel.")
except FileNotFoundError:
    pprint("Advertencia: El archivo 'desc_interfaces.xlsx' no se encontró. Asegúrate de que existe en la carpeta 'Files/'.")
except ValueError as e:
    pprint(f"Error en el archivo Excel: {e}")
    exit()

# Guardar resultados
def save_results(results_list, output_file):
    header = ['ip_address', 'expected_hostname', 'brand', 'interface', 'status', 'description', 'result']
    df_results = pd.DataFrame(results_list, columns=header)
    df_results.to_excel(output_file, index=False)
    pprint(f'Resultados guardados en {output_file}')

# Función para conectarse a un dispositivo
def connect_device(device_params, ip_address):
    device_params_local = device_params.copy()
    device_params_local['host'] = ip_address
    device_params_local['session_log'] = f"./session_logs/{ip_address}.log"
    return ConnectHandler(**device_params_local)

# Función genérica de manejo de errores
def handle_exceptions(ip_address, expected_hostname, vendor, err, results, results_lock):
    error_map = {
        NetMikoTimeoutException: "Error: Timeout",
        NetMikoAuthenticationException: "Error: Authentication failed",
        SSHException: "Error: SSH connection failed"
    }
    error_msg = error_map.get(type(err), f"Error: General {err}")
    pprint(f"{ip_address} - {error_msg}")
    
    error_data = {
        'ip_address': ip_address,
        'expected_hostname': expected_hostname,
        'brand': vendor,
        'interface': 'N/A',
        'status': 'N/A',
        'description': error_msg,
        'result': 'Error'
    }
    with results_lock:
        results.append(error_data)

# Función para extraer interfaces con MPLS/INT de dispositivos Cisco (IOS/IOS-XE)
def extract_cisco_interfaces(net_connect, ip_address, expected_hostname, results, results_lock):
    """
    Extrae interfaces con MPLS/INT de dispositivos Cisco (IOS/IOS-XE)
    o delega a la función Nexus si se detecta un Nexus.
    """
    current_prompt = net_connect.find_prompt()
    
    is_nexus = False
    try:
        # Send a basic command to get version information
        version_output = net_connect.send_command("show version | include Cisco", use_textfsm=False, read_timeout=10)
        if "Cisco Nexus" in version_output or "NX-OS" in version_output:
            is_nexus = True
            pprint(f"Detected Cisco Nexus device: {ip_address}")
        else:
            pprint(f"Detected Cisco IOS/IOS-XE device: {ip_address}")
    except Exception as e:
        pprint(f"Could not determine Cisco device type for {ip_address}: {e}. Assuming IOS/IOS-XE.")
        # If version command fails, proceed as IOS and let it fail if it's Nexus and commands don't match.

    if is_nexus:
        return extract_cisco_nexus_interfaces(net_connect, ip_address, expected_hostname, results, results_lock)
    
    output_interfaces = net_connect.send_command(
        f"show interface description | include MPLS|INT",
        expect_string=current_prompt,
        read_timeout=180
    )
    
    pattern = re.compile(
        r"^(?P<interface>\S+)\s+(?P<status>admin down|down|up)\s+(?:\S+)\s+(?P<description>.*(?:MPLS|INT).*)$",
        re.MULTILINE
    )
    
    found_interfaces_for_device = []
    matches = pattern.finditer(output_interfaces)
    for match in matches:
        interface = match.group("interface").strip()
        status = match.group("status").strip()
        description = match.group("description").strip()
        
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'brand': 'cisco',
            'interface': interface,
            'status': status,
            'description': description,
            'result': 'Success'
        })
    
    if not found_interfaces_for_device:
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'brand': 'cisco',
            'interface': 'N/A',
            'status': 'N/A',
            'description': 'No interfaces with MPLS or INT found',
            'result': 'No relevant interfaces'
        })
    
    with results_lock:
        results.extend(found_interfaces_for_device)

# Función para extraer interfaces con MPLS/INT de dispositivos Cisco Nexus
def extract_cisco_nexus_interfaces(net_connect, ip_address, expected_hostname, results, results_lock):
    current_prompt = net_connect.find_prompt()
    
    output_interfaces_raw = net_connect.send_command(
        f"show interface description | include MPLS|INT",
        expect_string=current_prompt,
        read_timeout=180
    )

    # Filter lines containing "MPLS" or "INT" in Python, similar to '| include'
    relevant_lines = [
        line for line in output_interfaces_raw.splitlines() 
        if "MPLS" in line or "INT" in line
    ]
    output_interfaces_filtered = "\n".join(relevant_lines)

    # Adjusted Regular Expression for Cisco Nexus output format
    # Example format: "Eth1/21        eth    40G     CO-TUB-FAL-CLR-MPLS-FEB0033-15M-PPAL"
    pattern = re.compile(
        r"^(?P<interface>\S+)\s+\S+\s+\S+\s+(?P<description>.*(?:MPLS|INT).*)$",
        re.MULTILINE
    )
    
    found_interfaces_for_device = []
    matches = pattern.finditer(output_interfaces_filtered) # Apply regex to the filtered lines
    for match in matches:
        interface = match.group("interface").strip()
        description = match.group("description").strip()
        
        status = "N/A (from description)" # Status is not directly available from this command on Nexus
        
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'brand': 'cisco',
            'interface': interface,
            'status': status,
            'description': description,
            'result': 'Success'
        })
    
    if not found_interfaces_for_device:
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'brand': 'cisco',
            'interface': 'N/A',
            'status': 'N/A',
            'description': 'No interfaces with MPLS or INT found (Cisco Nexus)',
            'result': 'No relevant interfaces'
        })
    
    with results_lock:
        results.extend(found_interfaces_for_device)

# Función para extraer interfaces con MPLS/INT de dispositivos Extreme
def extract_extreme_interfaces(net_connect, ip_address, expected_hostname, results, results_lock):
    """Extrae interfaces con MPLS/INT de dispositivos Extreme."""
    current_prompt = net_connect.find_prompt()
    output_interfaces = net_connect.send_command(
        f"show port description | include MPLS|MOV|IFX|CLR",
        expect_string=current_prompt,
        read_timeout=180
    )
    
    pattern = re.compile(
        r"^(?P<interface>\d+)\s+(?P<description>.*(?:MPLS|INT|MOV|IFX).*)$",
        re.MULTILINE 
    )
    
    found_interfaces_for_device = []
    matches = pattern.finditer(output_interfaces)
    for match in matches:
        interface = match.group("interface").strip()
        description = match.group("description").strip()
        
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'brand': 'extreme',
            'interface': interface,
            'status': 'N/A',
            'description': description,
            'result': 'Success'
        })

    if not found_interfaces_for_device:
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'brand': 'extreme',
            'interface': 'N/A',
            'status': 'N/A',
            'description': 'No interfaces with MPLS or INT found',
            'result': 'No relevant interfaces'
        })
    
    with results_lock:
        results.extend(found_interfaces_for_device)

# Función para extraer interfaces con MPLS/INT de dispositivos Huawei
def extract_huawei_interfaces(net_connect, ip_address, expected_hostname, results, results_lock):
    current_prompt = net_connect.find_prompt()
    output_interfaces = net_connect.send_command(
        f"display interface description | include MPLS|INET",
        expect_string=current_prompt,
        read_timeout=180
    )
    pattern = re.compile(
        r"^(?P<interface>\S+)\s+(?:\S+)\s+(?:\S+)\s+(?P<description>.*(?:MPLS|INET).*)$",
        re.MULTILINE
    )

    found_interfaces_for_device = []
    matches = pattern.finditer(output_interfaces)
    for match in matches:
        interface = match.group("interface").strip()
        description = match.group("description").strip()        
        status = "N/A (from description)" 
        
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'brand': 'huawei',
            'interface': interface,
            'status': status,
            'description': description,
            'result': 'Success'
        })
    
    if not found_interfaces_for_device:
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'brand': 'huawei',
            'interface': 'N/A',
            'status': 'N/A',
            'description': 'No interfaces with MPLS or INET found (Huawei)',
            'result': 'No relevant interfaces'
        })
    
    with results_lock:
        results.extend(found_interfaces_for_device)

# Diccionario de funciones por marca, ajustar si se requiere SSH o Telnet
BRAND_HANDLERS = {
    'cisco': {'params': dev.cisco_ssh, 'extract_func': extract_cisco_interfaces},
    'cisco_nexus': {'params': dev.cisco_ssh, 'extract_func': extract_cisco_nexus_interfaces}, 
    'extreme': {'params': dev.extreme_ssh, 'extract_func': extract_extreme_interfaces},
    'huawei': {'params': dev.huawei_ssh, 'extract_func': extract_huawei_interfaces}
}

def verify_device(row):
    ip_address = row['ip_address']
    expected_hostname = row.get('expected_hostname', 'N/A')
    vendor = row['vendor'].lower()

    handler = BRAND_HANDLERS.get(vendor)
    if not handler:
        handle_exceptions(ip_address, expected_hostname, vendor, f"Vendor '{vendor}' no soportado", results, results_lock)
        return

    device_params = handler['params']
    extract_func = handler['extract_func']
    
    try:
        with connect_device(device_params, ip_address) as net_connect:
            net_connect.enable() # Assuming enable is necessary for all

            # Execute the vendor-specific extraction function, passing results and results_lock
            extract_func(net_connect, ip_address, expected_hostname, results, results_lock)
                
    except Exception as err:
        handle_exceptions(ip_address, expected_hostname, vendor, err, results, results_lock)

# Ejecutar en múltiples hilos
with cf.ThreadPoolExecutor() as executor:
    futures = [executor.submit(verify_device, row) for _, row in df.iterrows()]
    for future in cf.as_completed(futures):
        future.result()

# Guardar resultados
output_excel_file = './Results/filtered_interfaces_summary.xlsx'
save_results(results, output_excel_file)

# Calcular y mostrar el tiempo total de ejecución
end_time = time.time()
elapsed_time = (end_time - start_time) / 60
pprint(f'Tiempo total de ejecución: {elapsed_time:.2f} minutos')