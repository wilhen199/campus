import concurrent.futures as cf
import threading
import pandas as pd
import re
from dotenv import load_dotenv
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
import devices as dev
from rich.pretty import pprint
import time

load_dotenv()

start_time = time.time()

# List to store results and its Lock for concurrency
results = []
results_lock = threading.Lock()

# Read data from the Excel file
try:
    df = pd.read_excel('./Files/desc_mpls.xlsx', 'Hoja1')
    if 'vendor' not in df.columns:
        raise ValueError("The column 'vendor' was not found in the Excel file.")
except FileNotFoundError:
    pprint("Warning: The file 'desc_mpls.xlsx' was not found. Make sure it exists in the 'Files/' folder.")
except ValueError as e:
    pprint(f"Excel file error: {e}")
    exit()

# Save results
def save_results(results_list, output_file):
    header = ['ip_address', 'expected_hostname','prompt', 'vendor', 'interface', 'new_description', 'result']
    df_results = pd.DataFrame(results_list, columns=header)
    df_results.to_excel(output_file, index=False)
    pprint(f'Resultados guardados en {output_file}')
    pprint(df_results)

# Function to connect to a device
def connect_device(device_params, ip_address):
    device_params_local = device_params.copy()
    device_params_local['host'] = ip_address
    device_params_local['session_log'] = f"./session_logs/{ip_address}.log"
    return ConnectHandler(**device_params_local)

# Generic error handling function
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
        'prompt': 'N/A',
        'vendor': vendor,
        'interface': 'N/A',
        'new_description': error_msg,
        'result': 'Error'
    }
    with results_lock:
        results.append(error_data)

# Function to set interfaces description on Cisco devices (IOS/IOS-XE)
def set_cisco_interfaces(net_connect, ip_address, expected_hostname, interface_device, description, results, results_lock):
    """
    Configure interfaces description on Cisco devices (IOS/IOS-XE).
    Delegates to the Nexus function if a Nexus is detected.
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
        return set_cisco_nexus_interfaces(net_connect, ip_address, expected_hostname, interface_device, description, results, results_lock)
    
    config_commands = [ f"interface {interface_device}",
                    f"description {description}",
                    "exit" ]
    
    output_interfaces = net_connect.send_command(
        f"show interface description | include {interface_device}",
        expect_string=current_prompt,
        read_timeout=180
    )
    
    net_connect.config_mode()
    
    # Configuración de la interfaz
    net_connect.send_config_set(config_commands)
    config = net_connect.send_command(f"show running-config interface {interface_device}", expect_string=current_prompt, read_timeout=180)
    new_description = re.search(r'description (.+)', config).group(1)
    pprint(f"Descripción actualizada: {ip_address} {expected_hostname} {interface_device} {new_description}")
    net_connect.save_config()
    net_connect.send_command_timing(f"copy running-config startup-config", strip_prompt=False, read_timeout=180)

    result_row = {
        'ip_address': ip_address,
        'expected_hostname': expected_hostname,
        'prompt': current_prompt,
        'vendor': 'Cisco',
        'interface': interface_device,
        'new_description': new_description,
        'result': 'Success'
    }
    with results_lock:
        results.append(result_row)

# Function to set interfaces description on Cisco Nexus devices
def set_cisco_nexus_interfaces(net_connect, ip_address, expected_hostname, interface_device, description, results, results_lock):
    current_prompt = net_connect.find_prompt()
    
    config_commands = [ f"interface {interface_device}",
                    f"description {description}",
                    "exit" ]
    
    output_interfaces = net_connect.send_command(
        f"show interface description | include {interface_device}",
        expect_string=current_prompt,
        read_timeout=180)
    
    net_connect.config_mode()
    
    # Configuration
    net_connect.send_config_set(config_commands)
    config = net_connect.send_command(f"show running-config interface {interface_device}", expect_string=current_prompt, read_timeout=180)
    new_description = re.search(r'description (.+)', config).group(1)
    pprint(f"Descripción actualizada: {ip_address} {expected_hostname} {interface_device} {new_description}")
    
    # Save configuration
    net_connect.save_config()
    net_connect.send_command_timing(f"copy running-config startup-config", strip_prompt=False, read_timeout=180)
    
    result_row = {
        'ip_address': ip_address,
        'expected_hostname': expected_hostname,
        'prompt': current_prompt,
        'vendor': 'Cisco',
        'interface': interface_device,
        'new_description': new_description,
        'result': 'Success'
    }
    with results_lock:
        results.append(result_row)

# Function to set interfaces on Extreme devices
def set_extreme_interfaces(net_connect, ip_address, expected_hostname,interface_device, description, results, results_lock):
    """Configure interfaces description on Extreme devices."""
    prompt_pattern = rf"({re.escape(expected_hostname)})\.\d+\s*#\s*"
    net_connect.send_command(f"show port no-refresh", expect_string=prompt_pattern, read_timeout=180)
    
    # Configuration
    config_commands = [ f"configure ports {interface_device} display-string {description}"]
    net_connect.send_config_set(config_commands)
    pprint(f"Descripción actualizada: {ip_address} {expected_hostname} {interface_device} {description}")
    net_connect.send_command(f"show port no-refresh", expect_string=prompt_pattern, read_timeout=180)
    
    # Save configuration
    net_connect.send_command_timing('save configuration', strip_prompt=False, strip_command=False)
    
    current_prompt = net_connect.find_prompt()
    result_row = {
        'ip_address': ip_address,
        'expected_hostname': expected_hostname,
        'prompt': current_prompt,
        'vendor': 'Extreme',
        'interface': interface_device,
        'new_description': description,
        'result': 'Success'
    }
    with results_lock:
        results.append(result_row)

# Function to set interfaces description on Huawei devices
def set_huawei_interfaces(net_connect, ip_address, expected_hostname, interface_device, description, results, results_lock):
    current_prompt = net_connect.find_prompt()
    net_connect.send_command(
        f"display interface description | include {interface_device}",
        expect_string=current_prompt,
        read_timeout=180
    )
    # Configuration mode
    def global_config():
        net_connect.send_command_timing('system-view', strip_prompt=False, strip_command=False)
    
    global_config()
    # Configuration command
    config_commands = [ f"interface {interface_device}",
                    f"description {description}",
                    "quit" ]
    
    net_connect.send_config_set(config_commands)
    config = net_connect.send_command(f"display current-configuration interface {interface_device}", expect_string=current_prompt, read_timeout=180)
    new_description = re.search(r'description (.+)', config).group(1)
    pprint(f"Descripción actualizada: {ip_address} {expected_hostname} {interface_device} {new_description}")
    
    # Save configuration
    net_connect.save_config()
    
    current_prompt = net_connect.find_prompt()
    result_row = {
        'ip_address': ip_address,
        'expected_hostname': expected_hostname,
        'prompt': current_prompt,
        'vendor': 'Huawei',
        'interface': interface_device,
        'new_description': new_description,
        'result': 'Success'
    }
    with results_lock:
        results.append(result_row)

# Dictionary of functions by brand, adjust if SSH or Telnet is required
BRAND_HANDLERS = {
    'cisco': {'params': dev.cisco_ssh, 'set_func': set_cisco_interfaces},
    'cisco_nexus': {'params': dev.cisco_ssh, 'set_func': set_cisco_nexus_interfaces}, 
    'extreme': {'params': dev.extreme_ssh, 'set_func': set_extreme_interfaces},
    'huawei': {'params': dev.huawei_ssh, 'set_func': set_huawei_interfaces}
}

def verify_device(row):
    ip_address = row['ip_address']
    interface_device = row['interface']
    description = row['description']
    expected_hostname = row.get('expected_hostname', 'N/A')
    vendor = row['vendor'].lower()

    handler = BRAND_HANDLERS.get(vendor)
    if not handler:
        handle_exceptions(ip_address, expected_hostname, vendor, f"Vendor '{vendor}' not supported", results, results_lock)
        return

    device_params = handler['params']
    set_func = handler['set_func']
    
    try:
        with connect_device(device_params, ip_address) as net_connect:
            net_connect.enable()

            # Execute the vendor-specific extraction function, passing results and results_lock
            set_func(net_connect, ip_address, expected_hostname, interface_device, description, results, results_lock)

    except Exception as err:
        handle_exceptions(ip_address, expected_hostname, vendor, err, results, results_lock)

# Run in multiple threads
with cf.ThreadPoolExecutor() as executor:
    futures = [executor.submit(verify_device, row) for _, row in df.iterrows()]
    for future in cf.as_completed(futures):
        future.result()

# Save results
output_excel_file = './Results/set_desc_interfaces_any_results.xlsx'
save_results(results, output_excel_file)

# Calculate and display the total execution time
end_time = time.time()
elapsed_time = (end_time - start_time) / 60
pprint(f'Total execution time: {elapsed_time:.2f} minutos')