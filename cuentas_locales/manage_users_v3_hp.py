import concurrent.futures as cf
import threading
import pandas as pd
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
import devices as dev
import credentials as cred
from rich.pretty import pprint

# Leer los datos del archivo xlsx usando pandas
df = pd.read_excel('./Files/HP_2.xlsx','Hoja1')

# Guardar el DataFrame en un archivo Excel
output_file = 'ctas_hp_results.xlsx'

# Datos comunes de conexión (SSH o Telnet con cuenta NT)
device_params = dev.hp_ssh

# Lista para almacenar los resultados
results = []
results_lock = threading.Lock()

def verify_device(row):
    ip_address = row['ip_address']
    expected_hostname = row.get('expected_hostname')
    
    # Actualizar los parámetros del dispositivo con la IP actual
    device_params_local = device_params.copy()
    device_params_local['host'] = ip_address
    
    pprint(f"Conectando a {ip_address}...")
    try:
        with ConnectHandler(**device_params_local, session_log='netmiko_session2.log') as net_connect:
            current_prompt = net_connect.find_prompt()

            # Entrar al modo configuración global del equipo y módulo aaa
            def global_config():
                net_connect.config_mode()
                net_connect.send_command_timing('aaa', strip_prompt=False, strip_command=False)
            
            # Obtener la configuración actual del dispositivo
            output = net_connect.send_command("display current-configuration | include local-user", read_timeout=180)

            # Extraer los nombres de usuarios creados
            usernames = output.splitlines()
            
            # Buscar todos los usuarios y generar comandos de eliminación
            delete_commands = []
            for line in usernames:
                if line.startswith(' local-user'):
                    user = line.split()[1]
                    delete_commands.append(f'undo local-user {user}')
            pprint(delete_commands)

            # Entrar al modo de configuración global con la función creada previamente
            global_config()
                        
            # Enviar comandos de eliminación de usuarios uno por uno
            for cmd in delete_commands:
                print(f"Eliminando usuario en {ip_address}: {cmd}")
                net_connect.send_command_timing(cmd, strip_prompt=False, strip_command=False)
                net_connect.send_command_timing('\n', strip_prompt=False, strip_command=False)  # Confirmar eliminación

            # Agregar 2 usuarios locales
            new_users = [
                f'local-user {cred.user_ntt} password irreversible-cipher {cred.pass_soportentt}', # usuario soportentt 
                f'local-user {cred.user_ntt} service-type terminal ssh', # service-type soportentt
                f'local-user {cred.user_campus} password irreversible-cipher {cred.pass_campus}', # usuario campus 
                f'local-user {cred.user_campus} service-type terminal ssh', # service-type campus
                'local-user policy password-force-change disable', #default password policy 
                'local-user policy service-type none' # defualt service-type policy 
            ]     
            net_connect.send_config_set(new_users)
            
            net_connect.save_config() # Guardar la configuración
            current_prompt = net_connect.find_prompt()
            result = f"{ip_address},{expected_hostname},{current_prompt},Usuarios eliminados y 2 usuarios agregados"
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