import concurrent.futures as cf
import threading
import pandas as pd
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
import devices as dev
from rich.pretty import pprint
import re
import os
from dotenv import load_dotenv

load_dotenv()

# Leer los datos del archivo xlsx usando pandas
df = pd.read_excel('./Files/ctas_huawei.xlsx','Hoja1')

# Guardar el DataFrame en un archivo Excel
output_file = './Results/huawei_results.xlsx'

# Datos comunes de conexión (SSH o Telnet con cuenta NT)
device_params = dev.huawei_ssh

# Lista para almacenar los resultados
results = []
results_lock = threading.Lock()

def verify_device(row):
    ip_address = row['ip_address']
    expected_hostname = row.get('expected_hostname')
    
    # Actualizar los parámetros del dispositivo con la IP actual
    device_params_local = device_params.copy()
    device_params_local['host'] = ip_address
    
    # Guardar logs ssh
    output_logs = f"./session_logs/{ip_address}.log"
    device_params_local['session_log'] = output_logs

    pprint(f"Conectando a {ip_address}...")
    try:
        with ConnectHandler(**device_params_local) as net_connect:
            current_prompt = net_connect.find_prompt()

            # Entrar al modo configuración global del equipo y módulo aaa
            def global_config():
                net_connect.config_mode()
                net_connect.send_command_timing('aaa', strip_prompt=False, strip_command=False)
            
            # Obtener la configuración actual del dispositivo
            output = net_connect.send_command("display current-configuration | include local-user", read_timeout=180)
            #print(output)
            # Extraer los nombres de usuarios creados
            #usernames = output.splitlines()
            local_users = set(re.findall(r' local-user (?!policy)(\S+)', output))

            # Imprimir la lista de usuarios
            pprint(f'Usuarios en {ip_address} {expected_hostname}: {local_users}')

            # Entrar al modo de configuración global con la función creada previamente
            global_config()
            
            allowed_users = {os.getenv('user_campus'), os.getenv('user_ntt')}

            if local_users == allowed_users:
                pprint(f"En {ip_address} {expected_hostname},solo están creados los usuarios permitidos: {', '.join(local_users)}")
                result = f"{ip_address},{expected_hostname},{current_prompt},Usuarios permitidos ya configurados"
            else:
                delete_commands = [f'undo local-user {user}' for user in local_users if user not in allowed_users]
                pprint(f"Comando a ejecutar en {ip_address}: {delete_commands}")

                # Enviar comandos de eliminación
                for cmd in delete_commands:
                    pprint(f"Eliminando usuario en {ip_address} {expected_hostname} : {cmd}")
                    net_connect.send_command_timing(cmd, strip_prompt=False, strip_command=False)
                    net_connect.send_command_timing('\n', strip_prompt=False, strip_command=False)  # Confirmar eliminación

                # Agregar los usuarios no permitidos si no están presentes
                missing_users = allowed_users - local_users
                for user in missing_users:
                    new_users = [
                    f'local-user {user} password irreversible-cipher {os.getenv(f'pass_{user}')}', # usuario soportentt 
                    f'local-user {user} service-type terminal ssh', # service-type soportentt
                    ]
                    if new_users:
                        pprint(f"Agregando usuarios en {ip_address} {expected_hostname}: {new_users}")
                        net_connect.send_config_set(new_users)
            
                net_connect.save_config() # Guardar la configuración
                current_prompt = net_connect.find_prompt()
                missing_users_str = ', '.join(missing_users) if missing_users else "0"
                result = f"{ip_address},{expected_hostname},{current_prompt},Usuarios actualizados: eliminados no permitidos y añadidos faltantes {missing_users_str}"
                print(result)
    
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
header = ['ip_address', 'expected_hostname', 'prompt', 'result']

data = []
for result in results:
    fields = result.split(',', 3)
    data.append(fields)

# Crear un DataFrame con los resultados
df = pd.DataFrame(data, columns=header)

# Guardar el DataFrame en un archivo Excel
df.to_excel(output_file, index=False)
pprint(f'Resultados guardados en {output_file}')