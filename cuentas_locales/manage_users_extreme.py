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
df = pd.read_excel('./Files/extreme.xlsx','Hoja1')

# Guardar el DataFrame en un archivo Excel
output_file = './Results/extreme_results.xlsx'

# Datos comunes de conexión (SSH o Telnet con cuenta NT)
#device_params = dev.extreme_ssh
device_params = dev.extreme_telnet


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
            #Obtener prompt del equipo
            current_prompt = net_connect.find_prompt()
            
            # Obtener la configuración actual del dispositivo
            output = net_connect.send_command("show accounts", expect_string=current_prompt, read_timeout=180)

            # Extraer los nombres de usuario usando una expresión regular
            usernames = re.findall(r'^\s+([a-zA-Z0-9]+)', output, re.MULTILINE)
            existing_users = usernames[1:]
            
            # Imprimir la lista de usuarios
            pprint(f"Usuarios en {ip_address} {expected_hostname}: {existing_users}")

            allowed_users = {os.getenv('user_campus'), os.getenv('user_ntt')}

            if set(existing_users) == allowed_users: # Elimina duplicados en lista existing_users y compara con usuarios permitidos
                pprint(f"En {ip_address} {expected_hostname}, solo están creados los usuarios permitidos: {', '.join(existing_users)}")
                result = f"{ip_address},{expected_hostname},{current_prompt},Usuarios permitidos ya configurados"                
            else:
                delete_commands = [f'delete account {user}' for user in existing_users if user not in allowed_users]
                pprint(f"Comando a ejecutar en {ip_address}: {delete_commands}")
            
            # Enviar comandos de eliminación
                for cmd in delete_commands:
                    pprint(f"Eliminando usuario en {ip_address}: {cmd}")
                    net_connect.send_command_timing(cmd, strip_prompt=False, strip_command=False)
                    net_connect.send_command_timing('\n', strip_prompt=False, strip_command=False)  # Confirmar eliminación
                
                # Agregar los usuarios permitidos si no están presentes
                missing_users = allowed_users - set(existing_users)
                new_users = [f'create account admin {user} {os.getenv(f"pass_{user}")}' for user in missing_users]
                
                if new_users:
                    pprint(f"Agregando usuarios en {ip_address} {expected_hostname}: {new_users}")
                    net_connect.send_config_set(new_users)

                # Comandos para guardar la configuración
                net_connect.send_command_timing('save configuration', strip_prompt=False, strip_command=False)
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

# # Encabezados para guardar resultados en un archivo xlsx:
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