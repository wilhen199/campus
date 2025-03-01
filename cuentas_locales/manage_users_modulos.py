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

# Iniciar el tiempo de ejecución
start_time = time.time()

# Leer los datos del archivo Excel
df = pd.read_excel('./Files/dispositivos.xlsx', 'Hoja1')

# Guardar resultados
def save_results(results, output_file):
    header = ['ip_address', 'expected_hostname', 'prompt', 'result']
    data = []
    for result in results:
        fields = result.split(',', 3)
        data.append(fields)
    df = pd.DataFrame(data, columns=header)
    #df = pd.DataFrame(results, columns=header)
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
    return f"{ip_address},{expected_hostname},,{error_msg}"

# Función para gestionar usuarios en Cisco
def manage_cisco(net_connect, ip_address, expected_hostname):
    current_prompt = net_connect.find_prompt()
    device_info = net_connect.send_command("show version", expect_string=current_prompt, read_timeout=180)
    output = net_connect.send_command("show running-config | include username")
    existing_users = [line.split()[1] for line in output.splitlines() if line.startswith('username')]
    allowed_users = {os.getenv('user_campus'), os.getenv('user_ntt')}

    delete_commands = [f'no username {user}' for user in existing_users if user not in allowed_users]
    missing_users = allowed_users - set(existing_users)
    if "Cisco Nexus" in device_info: # Si el dispositivo es Cisco Nexus, ejecuta este bloque
        new_user_commands = [f'username {user} role network-admin password {os.getenv(f"pass_{user}")}' for user in missing_users]
    else: # Si no es Cisco Nexus, ejecuta este bloque
        new_user_commands = [f'username {user} privilege 15 secret {os.getenv(f"pass_{user}")}' for user in missing_users]

    if delete_commands or new_user_commands:
        net_connect.config_mode()
        for cmd in delete_commands:
#            net_connect.send_command_timing(cmd)
            net_connect.send_command_timing(cmd, strip_prompt=False, strip_command=False)
            net_connect.send_command_timing('\n', strip_prompt=False, strip_command=False)  # Confirmar eliminación
        net_connect.send_config_set(new_user_commands)
        if "Cisco Nexus" in device_info:
            net_connect.send_command_timing("copy run start", strip_prompt=False, strip_command=False)
        else:
            net_connect.send_command_timing("wr", strip_prompt=False, strip_command=False)

    return f"{ip_address},{expected_hostname},{current_prompt},Usuarios actualizados"

# Función para gestionar usuarios en Extreme
def manage_extreme(net_connect, ip_address, expected_hostname):
    current_prompt = net_connect.find_prompt()
    output = net_connect.send_command("show accounts")
    existing_users = re.findall(r'^\s+([a-zA-Z0-9]+)', output, re.MULTILINE)[1:]
    allowed_users = {os.getenv('user_campus'), os.getenv('user_ntt')}

    delete_commands = [f'delete account {user}' for user in existing_users if user not in allowed_users]
    missing_users = allowed_users - set(existing_users)
    new_users = [f'create account admin {user} {os.getenv(f"pass_{user}")}' for user in missing_users]

    if delete_commands or new_users:
        for cmd in delete_commands:
            net_connect.send_command_timing(cmd)
        net_connect.send_config_set(new_users)
        net_connect.send_command_timing('save configuration')

    return f"{ip_address},{expected_hostname},{current_prompt},Usuarios actualizados"

# Función para gestionar usuarios en Huawei
def manage_huawei(net_connect, ip_address, expected_hostname):
    current_prompt = net_connect.find_prompt()
    output = net_connect.send_command("display current-configuration | include local-user")
    local_users = set(re.findall(r' local-user (?!policy)(\S+)', output))
    allowed_users = {os.getenv('user_campus'), os.getenv('user_ntt')}
    
    if local_users ==  allowed_users:
        return f"{ip_address},{expected_hostname},{current_prompt},Usuarios actualizados"
    else:
        delete_commands = [f'undo local-user {user}' for user in local_users if user not in allowed_users]
        net_connect.config_mode()
        net_connect.send_command_timing('aaa', strip_prompt=False, strip_command=False)

        for cmd in delete_commands:
            net_connect.send_command_timing(cmd)
            net_connect.send_command_timing('\n')
            net_connect.save_config()
        

    missing_users = allowed_users - local_users
    for user in missing_users:
        new_users = [
            f'local-user {user} password irreversible-cipher {os.getenv(f"pass_{user}")}',
						f'local-user {user} service-type terminal ssh'
            ]
        if new_users:
            net_connect.config_mode()
            net_connect.send_command_timing('aaa', strip_prompt=False, strip_command=False)

            net_connect.send_config_set(new_users)
    net_connect.save_config()
    
    return f"{ip_address},{expected_hostname},{current_prompt},Usuarios actualizados"

# Diccionario de funciones por marca
BRAND_FUNCTIONS = {
    'Cisco': (dev.cisco_ssh, manage_cisco),
    'Extreme': (dev.extreme_ssh, manage_extreme),
    'Huawei': (dev.huawei_ssh, manage_huawei)
}

# Lista para almacenar resultados
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
dispositivo_output = './Results/dispositivos_results.xlsx'
save_results(results, dispositivo_output)

# Calcular y mostrar el tiempo total de ejecución
end_time = time.time()
elapsed_time = (end_time - start_time) / 60
pprint(f'Tiempo total de ejecución: {elapsed_time:.2f} minutos')