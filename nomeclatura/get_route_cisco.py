import concurrent.futures as cf
import threading
import pandas as pd
import re
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
import devices as dev
from rich.pretty import pprint
import time

start_time = time.time()

# Leer los datos del archivo xlsx usando pandas
df = pd.read_excel('./Files/route_cisco.xlsx','Hoja1')

# Guardar el DataFrame en un archivo Excel
output_file = './Results/route_cisco_results.xlsx'

# # Datos comunes de conexión (SSH o Telnet con cuenta NT, mantenimiento, fala04, faladmin)
device_params = dev.cisco_ssh
#device_params = dev.cisco_ssh_mante
#device_params = dev.cisco_ssh_fala04
#device_params = dev.cisco_ssh_faladmin
#device_params = dev.cisco_telnet
#device_params = dev.cisco_telnet_mante
#device_params = dev.cisco_telnet_fala04
#device_params = dev.cisco_telnet_faladmin

# Lista para almacenar los resultados
results = []
results_lock = threading.Lock()

def verify_device(row):
    ip_address = row['ip_address']
    expected_hostname = row.get('expected_hostname')  # Obtener el nombre del host esperado si está disponible
    
    # Actualizar los parámetros del dispositivo con la IP actual
    device_params_local = device_params.copy()
    device_params_local['host'] = ip_address

    # Guardar logs ssh
    output_logs = f"./session_logs/session_log_{ip_address}.log"
    device_params_local['session_log'] = output_logs

    pprint(f"Conectando a {ip_address}...")
    try:
        with ConnectHandler(**device_params_local) as net_connect:
            # Entrar al modo enable
            net_connect.enable()
            current_prompt = net_connect.find_prompt()

            route = net_connect.send_command('show ip route 0.0.0.0', expect_string=current_prompt, read_timeout=180)
            protocolo = re.search(r'Known via\s+"([^"]+)"', route).group(1)

            result = f"{ip_address},{expected_hostname},{current_prompt},{protocolo}"
            net_connect.disconnect()            
            
    except NetMikoTimeoutException:
        print(f"Timeout al conectar a {ip_address}")
        result = f"{ip_address},{expected_hostname},,Error: Timeout"
    except NetMikoAuthenticationException:
        print(f"Autenticación fallida al conectar a {ip_address}")
        result = f"{ip_address},{expected_hostname},,Error: Authentication failed"
    except (SSHException):
        print (f'SSH might not be enabled: {ip_address}')
        result = f"{ip_address},{expected_hostname},,Error: SSH connection failed"
    except Exception as err:
        print(f"Error al conectar a {ip_address}: {err}")
        result = f"{ip_address},{expected_hostname},,Error: General {err}"
    with results_lock:
        results.append(result)

# Create a ThreadPoolExecutor to manage threads
with cf.ThreadPoolExecutor() as executor:
    futures = [executor.submit(verify_device, row) for index, row in df.iterrows()]

    # Ensure all threads have completed
    for future in cf.as_completed(futures):
        future.result()

# Encabezados para guardar resultados en un archivo xlsx:
header = ['ip_address', 'expected_hostname', 'prompt', 'protocolo']

data = []
for result in results:
    fields = result.split(',', 3)
    data.append(fields)

# Crear un DataFrame con los resultados
df = pd.DataFrame(data, columns=header)

# Guardar el DataFrame en un archivo Excel
df.to_excel(output_file, index=False)
pprint(f'Resultados guardados en {output_file}')

end_time = time.time()
elapsed_time = (end_time - start_time) / 60
pprint(f'Total execution time: {elapsed_time:.2f} minutos')