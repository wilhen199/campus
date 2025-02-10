import threading
import concurrent.futures as cf
import pandas as pd
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
import devices as dev
from rich.pretty import pprint
import re

# Leer los datos del archivo xlsx usando pandas
df = pd.read_excel('./Files/snmp_extreme_2_wf.xlsx')

# Guardar el DataFrame en un archivo Excel
output_file = 'snmp_extreme_2_fala04_telnet_results.xlsx'

# Datos comunes de conexión (SSH o Telnet con cuenta NT, mantenimiento, fala04, faladmin)
device_params = dev.extreme_ssh
#device_params = dev.extreme_ssh_mante
#device_params = dev.extreme_ssh_fala04
#device_params = dev.extreme_ssh_faladmin
#device_params = dev.extreme_telnet
#device_params = dev.extreme_telnet_mante
#device_params = dev.extreme_telnet_fala04
#device_params = dev.extreme_telnet_faladmin



# Lista para almacenar los resultados
results = []
results_lock = threading.Lock()

def verify_device(row):
    ip_address = row['ip_address']
    expected_hostname = row.get('expected_hostname')  # Obtener el nombre del host esperado si está disponible
    
    # Actualizar los parámetros del dispositivo con la IP actual
    device_params_local = device_params.copy()
    device_params_local['host'] = ip_address
    
    
    pprint(f"Conectando a {ip_address}...")
    try:
        with ConnectHandler(**device_params_local) as net_connect:
            # Entrar al modo enable
            net_connect.enable()
            Heartbeat = net_connect.is_alive()
            prompt = net_connect.find_prompt()
            output_snmp = net_connect.send_command('sh configuration | i community', read_timeout=180)
            # Comparar el resultado isalive
            if Heartbeat:
                result = f'{ip_address},{expected_hostname},alive,{prompt},{output_snmp}'
                print(result)
            else:
                result = f'{ip_address},{expected_hostname},not alive,,'
                print(result)
                
    except NetMikoTimeoutException:
        print(f"Timeout al conectar a {ip_address}")
        result = f"{ip_address},{expected_hostname},,,Error: Timeout"
    except NetMikoAuthenticationException:
        print(f"Autenticación fallida al conectar a {ip_address}")
        result = f"{ip_address},{expected_hostname},,,Error: Authentication failed"
    except (SSHException):
        print (f'SSH might not be enabled: {ip_address}')
        result = f"{ip_address},{expected_hostname},,,Error: SSH connection failed"
    except Exception as err:
        print(f"Error al conectar a {ip_address}: {err}")
        result = f"{ip_address},{expected_hostname},,,Error: General {err}"
    with results_lock:
        results.append(result)

# Create a ThreadPoolExecutor to manage threads
with cf.ThreadPoolExecutor() as executor:
    futures = [executor.submit(verify_device, row) for index, row in df.iterrows()]

    # Ensure all threads have completed
    for future in cf.as_completed(futures):
        future.result()

# Encabezados para guardar resultados en un archivo xlsx:
header = ['ip_address', 'expected_hostname', 'alive?', 'prompt', 'SNMP']


data = []
for result in results:
    fields = result.split(',', 4)
    data.append(fields)

# Crear un DataFrame con los resultados
df = pd.DataFrame(data, columns=header)

# Función para eliminar caracteres no permitidos
def clean_string(s):
    if isinstance(s, str):
        # Reemplazar los caracteres no permitidos con un string vacío
        return re.sub(r'[\x00-\x1F\x7F]', '', s)
    return s

# Aplicar la función a todo el DataFrame
df_clean = df.map(clean_string)

# Ahora escribe el DataFrame limpio a Excel
df_clean.to_excel(output_file, index=False)
pprint(f'Resultados guardados en {output_file}')