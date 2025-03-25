import concurrent.futures as cf
import threading
import pandas as pd
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
import devices as dev
from rich.pretty import pprint
import re

# Leer los datos del archivo xlsx usando pandas
df = pd.read_excel('./Files/vstack.xlsx','Hoja1')

# Guardar el DataFrame en un archivo Excel
output_file = './Results/set_no_vstack_results.xlsx'

# Datos comunes de conexión para netmiko (ajustar según sea necesario)
device_params = dev.cisco_ssh
#device_params = dev.cisco_telnet

# Lista para almacenar los resultados
results = []
results_lock = threading.Lock()

def verify_device(row):
    ip_address = row['ip_address']
    expected_hostname = row.get('expected_hostname')  # Obtener el nombre del host esperado si está disponible
    result = f"{ip_address},{expected_hostname},,Error: Salida inesperada"  # Inicializar result


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
            set_no_vstack = ["no vstack"]
            # Entrar a modo configuración global y ejecutar comando
            net_connect.config_mode()
            
            net_connect.send_config_set(set_no_vstack)
            # Salir de modo configuración global y guardar configuración
            net_connect.exit_config_mode()
            net_connect.save_config()
            result = f"{ip_address},{expected_hostname},{current_prompt},{"vstack deshabilitado"}"
            
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
header = ['ip_address', 'expected_hostname', 'prompt', 'result']  # Definir el encabezado del archivo

data = []
for result in results:
    fields = result.split(',', 3)
    data.append(fields)

# Crear un DataFrame con los resultados
df = pd.DataFrame(data, columns=header)

# Guardar el DataFrame en un archivo Excel
df.to_excel(output_file, index=False)
pprint(f'Resultados guardados en {output_file}')