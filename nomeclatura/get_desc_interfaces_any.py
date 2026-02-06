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
    df = pd.read_excel('./Files/desc_interfaces.xlsx', 'Hoja1')
    if 'vendor' not in df.columns:
        raise ValueError("The column 'vendor' was not found in the Excel file.")
except FileNotFoundError:
    pprint("Warning: The file 'desc_interfaces.xlsx' was not found. Make sure it exists in the 'Files/' folder.")
except ValueError as e:
    pprint(f"Excel file error: {e}")
    exit()

# Save results
def save_results(results_list, output_file):
    header = ['ip_address', 'expected_hostname', 'vendor', 'interface', 'status', 'description', 'result']
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
        'brand': vendor,
        'interface': 'N/A',
        'status': 'N/A',
        'description': error_msg,
        'result': 'Error'
    }
    with results_lock:
        results.append(error_data)

# Function to extract interfaces from Cisco devices (IOS/IOS-XE/NX-OS)
def extract_cisco_interfaces(net_connect, ip_address, expected_hostname, results, results_lock):
    """
    Extracts interfaces from Cisco devices (IOS/IOS-XE)
    or delegates to the Nexus function if a Nexus is detected.
    """
    current_prompt = net_connect.find_prompt()
    
    is_nexus = False
    try:
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
        f"show interface description",
        expect_string=current_prompt,
        read_timeout=180
    )
    
    lines = output_interfaces.splitlines()
    found_interfaces_for_device = []
    for line in lines:
        if not line.strip() or line.lower().startswith('interface'):
            continue
        parts = re.split(r'\s{3,}', line.strip(), maxsplit=3)
        if len(parts) < 3:
            continue  
        interface = parts[0].strip()
        status = parts[1].strip()
        description = parts[3].strip() if len(parts) > 3 else ''
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
            'description': 'No interfaces with MPLS | INT | P2P found',
            'result': 'No relevant interfaces'
        })
    
    with results_lock:
        results.extend(found_interfaces_for_device)

# Function to extract interfaces from Cisco Nexus devices
def extract_cisco_nexus_interfaces(net_connect, ip_address, expected_hostname, results, results_lock):
    current_prompt = net_connect.find_prompt()
    
    output_interfaces_raw = net_connect.send_command(
        f"show interface description",
        expect_string=current_prompt,
        read_timeout=180
    )

    lines = output_interfaces_raw.splitlines()
    found_interfaces_for_device = []
    for line in lines:
        if not line.strip() or line.lower().startswith('Eth'):
            continue
        parts = re.split(r'\s{3,}', line.strip(), maxsplit=3)
        if len(parts) < 3:
            continue  
        interface = parts[0].strip()
        speed = parts[2].strip()
        description = parts[3].strip() if len(parts) > 3 else ''
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'brand': 'cisco',
            'interface': interface,
            'status': speed,
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

# Function to extract interfaces from Extreme devices
def extract_extreme_interfaces(net_connect, ip_address, expected_hostname, results, results_lock):
    """Extracts interfaces from Extreme devices."""
    current_prompt = net_connect.find_prompt()
    output_interfaces = net_connect.send_command(
        f"show port description ",
        expect_string=current_prompt,
        read_timeout=180
    )
    
    lines = output_interfaces.splitlines()
    header_idx = None
    header_line = None
    for i, ln in enumerate(lines):
        if 'Port' in ln and 'Display' in ln:
            header_idx = i
            header_line = ln
            break

    found_interfaces_for_device = []

    if header_line:
        disp_start = header_line.find('Display')
        desc_start = header_line.find('Description')
        if disp_start == -1:
            disp_start = 6
        if desc_start == -1:
            desc_start = disp_start + 20

        for ln in lines[header_idx+1:]:
            if not ln.strip() or ln.strip().startswith('====='):
                continue

            ln_padded = ln + ' ' * (max(0, desc_start - len(ln)))
            interface = ln_padded[:disp_start].strip()
            display = ln_padded[disp_start:desc_start].strip()

            if not display:
                continue
            
            found_interfaces_for_device.append({
                'ip_address': ip_address,
                'expected_hostname': expected_hostname,
                'brand': 'extreme',
                'interface': interface,
                'status': 'N/A',
                'description': display,
                'result': 'Success'
            })
    else:
        # Fallback: try regex per line
        pattern = re.compile(r"^\s*(?P<interface>\d+)\s+(?P<description>.*?)\s*$", re.MULTILINE)
        matches = pattern.finditer(output_interfaces)
        for match in matches:
            interface = match.group("interface").strip()
            description = match.group("description").strip()
            if not description:
                continue
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
            'description': 'No interfaces description found',
            'result': 'No relevant interfaces'
        })
    
    with results_lock:
        results.extend(found_interfaces_for_device)

# Function to extract interfaces with MPLS/INT from Huawei devices
def extract_huawei_interfaces(net_connect, ip_address, expected_hostname, results, results_lock):
    current_prompt = net_connect.find_prompt()
    output_interfaces = net_connect.send_command(
        f"display interface description",
        expect_string=current_prompt,
        read_timeout=180
    )

    lines = output_interfaces.splitlines()
    header_idx = None
    for i, ln in enumerate(lines):
        if 'Interface' in ln and 'PHY' in ln and 'Protocol' in ln:
            header_idx = i
            break

    pattern = re.compile(r"^(?P<interface>\S+)\s+(?P<status_phy>\S+)\s+(?:\S+)\s+(?P<description>.*)$")

    found_interfaces_for_device = []
    if header_idx is not None:
        for ln in lines[header_idx+1:]:
            if not ln.strip():
                continue
            m = pattern.match(ln)
            if not m:
                continue
            interface = m.group("interface").strip()
            description = m.group("description").strip()
            status_phy = m.group("status_phy").strip()

            if not re.search(r"\d", interface):
                continue
            found_interfaces_for_device.append({
                'ip_address': ip_address,
                'expected_hostname': expected_hostname,
                'brand': 'huawei',
                'interface': interface,
                'status': status_phy,
                'description': description,
                'result': 'Success'
            })
    else:

        matches = pattern.finditer(output_interfaces)
        for match in matches:
            interface = match.group("interface").strip()
            description = match.group("description").strip()
            status_phy = match.group("status_phy").strip()
            if not re.search(r"\d", interface):
                continue
            found_interfaces_for_device.append({
                'ip_address': ip_address,
                'expected_hostname': expected_hostname,
                'brand': 'huawei',
                'interface': interface,
                'status': status_phy,
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
            'description': 'N/A',
            'result': 'No relevant interfaces'
        })
    
    with results_lock:
        results.extend(found_interfaces_for_device)

# Dictionary of functions by brand, adjust if SSH or Telnet is required
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
        handle_exceptions(ip_address, expected_hostname, vendor, f"Vendor '{vendor}' not supported", results, results_lock)
        return

    device_params = handler['params']
    extract_func = handler['extract_func']
    
    try:
        with connect_device(device_params, ip_address) as net_connect:
            net_connect.enable()

            # Execute the vendor-specific extraction function, passing results and results_lock
            extract_func(net_connect, ip_address, expected_hostname, results, results_lock)
                
    except Exception as err:
        handle_exceptions(ip_address, expected_hostname, vendor, err, results, results_lock)

# Run in multiple threads
with cf.ThreadPoolExecutor() as executor:
    futures = [executor.submit(verify_device, row) for _, row in df.iterrows()]
    for future in cf.as_completed(futures):
        future.result()

# Save results
output_excel_file = './Results/all_interfaces_results.xlsx'
save_results(results, output_excel_file)

# Calculate and display the total execution time
end_time = time.time()
elapsed_time = (end_time - start_time) / 60
pprint(f'Total execution time: {elapsed_time:.2f} minutos')