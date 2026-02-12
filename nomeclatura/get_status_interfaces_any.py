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
    header = ['ip_address', 'expected_hostname', 'vendor', 'interface','status', 'description','duplex' , 'result']
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
        'vendor': vendor,
        'interface': 'N/A',
        'status': 'N/A',
        'description': error_msg,
        'result': 'Error'
    }
    with results_lock:
        results.append(error_data)

# Function to extract interfaces from Cisco devices (IOS/IOS-XE/NX-OS)
def extract_cisco_interfaces(net_connect, ip_address, expected_hostname, results, results_lock):
    current_prompt = net_connect.find_prompt()
    
    output_interfaces = net_connect.send_command(
        f"show interface status",
        expect_string=current_prompt,
        read_timeout=180
    )

    lines = output_interfaces.splitlines()
    found_interfaces_for_device = []

    # Try to detect header line and get column positions
    header_idx = None
    header_line = None
    for i, ln in enumerate(lines):
        if re.search(r"\bPort\b", ln, re.I) and re.search(r"\bStatus\b", ln, re.I):
            header_idx = i
            header_line = ln
            break

    if header_line:
        lower = header_line.lower()
        port_start = lower.find('port') if lower.find('port') != -1 else 0
        name_start = lower.find('name') if lower.find('name') != -1 else port_start + 10
        status_start = lower.find('status') if lower.find('status') != -1 else name_start + 20
        vlan_start = lower.find('vlan') if lower.find('vlan') != -1 else status_start + 15
        duplex_start = lower.find('duplex') if lower.find('duplex') != -1 else vlan_start + 15

        # Decide where data rows start: some IOS outputs have a secondary header line (like a '#')
        data_start = header_idx + 1
        if header_idx + 1 < len(lines):
            next_line = lines[header_idx + 1].strip()
            # If the next line looks like a header (starts with '#' or contains non-data separators), skip it
            if next_line.startswith('#') or next_line.startswith('---') or next_line.startswith('===') or not re.search(r'\d', next_line):
                data_start = header_idx + 2
            else:
                # also check token candidate to see if it's an interface like Gi1/0/1
                parts_next = re.split(r'\s{2,}', next_line)
                candidate = parts_next[0].strip() if parts_next else ''
                if not re.search(r'[A-Za-z]', candidate) and not re.search(r'\d', candidate):
                    data_start = header_idx + 2

        # iterate data rows
        for ln in lines[data_start:]:
            if not ln.strip():
                continue
            if ln.strip().startswith('=====') or ln.strip().startswith('----'):
                continue

            ln_padded = ln + ' ' * (max(0, duplex_start - len(ln)))
            interface = ln_padded[port_start:name_start].strip()
            description = ln_padded[name_start:status_start].strip()
            status = ln_padded[status_start:vlan_start].strip()
            duplex_field = ln_padded[duplex_start:].strip()
            duplex = duplex_field.split()[0] if duplex_field else ''

            # If slicing didn't capture interface (indexing mismatch), try a robust token fallback
            if not interface or not re.search(r"\d", interface):
                parts = re.split(r'\s{2,}', ln.strip())
                if parts:
                    candidate = parts[0].strip()
                    if candidate and re.search(r"\d", candidate):
                        interface = candidate
                        # adjust other fields from tokens when available
                        description = parts[1].strip() if len(parts) > 1 else description
                        status = parts[2].strip() if len(parts) > 2 else status
                        # duplex may be in parts[3] or parts[4]
                        if len(parts) > 4:
                            duplex = parts[4].strip()
                        elif len(parts) > 3:
                            duplex = parts[3].strip()
                    else:
                        continue
                else:
                    continue

            found_interfaces_for_device.append({
                'ip_address': ip_address,
                'expected_hostname': expected_hostname,
                'vendor': 'cisco',
                'interface': interface,
                'status': status,
                'description': description,
                'duplex': duplex,
                'result': 'Success'
            })
    else:
        # Fallback: split by 2+ spaces and assign fields with defensive checks
        for line in lines:
            if not line.strip() or line.lower().startswith('port'):
                continue
            parts = re.split(r'\s{2,}', line.strip())
            if len(parts) < 3:
                continue
            interface = parts[0]
            description = parts[1].strip() if len(parts) > 1 else ''
            status = parts[2].strip() if len(parts) > 2 else ''
            if len(parts) > 4:
                duplex = parts[4].strip()
            elif len(parts) > 3:
                duplex = parts[3].strip()
            else:
                duplex = ''

            if not interface or not re.search(r"\d", interface):
                continue

            found_interfaces_for_device.append({
                'ip_address': ip_address,
                'expected_hostname': expected_hostname,
                'vendor': 'cisco',
                'interface': interface,
                'status': status,
                'description': description,
                'duplex': duplex,
                'result': 'Success'
            })

    if not found_interfaces_for_device:
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'vendor': 'cisco',
            'interface': 'N/A',
            'status': 'N/A',
            'description': 'N/A',
            'duplex': 'N/A',
            'result': 'No relevant interfaces'
        })
    
    with results_lock:
        results.extend(found_interfaces_for_device)

# Function to extract interfaces from Extreme devices
def extract_extreme_interfaces(net_connect, ip_address, expected_hostname, results, results_lock):
    """Extracts interfaces from Extreme devices."""
    current_prompt = net_connect.find_prompt()
    output_interfaces = net_connect.send_command(
        f"show port no-refresh ",
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
        # Combine header line with the following line if it contains secondary headers (State/Link)
        combined_header = header_line
        if header_idx + 1 < len(lines) and any(k in lines[header_idx+1] for k in ('State', 'Link', '#')):
            combined_header = header_line + ' ' + lines[header_idx+1]

        lower = combined_header.lower()
        port_start = lower.find('port') if lower.find('port') != -1 else 0
        display_start = lower.find('display', port_start + 1) if lower.find('display', port_start + 1) != -1 else port_start + 6
        vlan_start = lower.find('vlan', display_start + 1) if lower.find('vlan', display_start + 1) != -1 else display_start + 12
        # detect positions of 'state' occurrences (Port State and Link State)
        state_positions = [m.start() for m in re.finditer(r'state', lower)]
        status1_start = state_positions[0] if len(state_positions) > 0 else -1 # Port State
        status2_start = state_positions[1] if len(state_positions) > 1 else -1 # Link State
        duplex_start = lower.find('duplex') if lower.find('duplex') != -1 else (status2_start if status2_start != -1 else (status1_start if status1_start != -1 else display_start + 36))

        # start after the secondary header line (the second header row with '#' and State/Link)
        for ln in lines[header_idx+2:]:
            if not ln.strip() or ln.strip().startswith('=====') or ln.strip().startswith('----'):
                continue

            ln_padded = ln + ' ' * (max(0, duplex_start - len(ln)))
            interface = ln_padded[port_start:display_start].strip()
            # Tokenize early so it's always available for fallback logic
            parts = re.split(r'\s{2,}', ln.strip())
            # Prefer slicing between Display and VLAN columns to get the Display String
            display_slice = ln_padded[display_start:vlan_start].strip()
            # only accept display_slice if it doesn't look like a VLAN token (e.g. '(0002)' or 'Default')
            if display_slice and not re.match(r'^\(?\d+\)?$', display_slice) and display_slice.lower() not in ('default', 'none', 'n/a'):
                description = display_slice
            else:
                # fallback: tokenized parsing only if token looks like a real display (letters, not VLAN numeric)
                if len(parts) > 1 and parts[1].strip() and re.search(r'[A-Za-z]', parts[1].strip()) and not re.match(r'^\(?\d+\)?$', parts[1].strip()) and parts[1].strip().lower() not in ('default', 'none', 'n/a'):
                    description = parts[1].strip()
                else:
                    description = ''

            # Try to extract status using column slices (from second header positions)
            status = ''
            if status1_start != -1 and status2_start != -1 and status2_start > status1_start:
                status1 = ln_padded[status1_start:status2_start].strip()
                status2 = ln_padded[status2_start:duplex_start].strip()
                status = (status1 + ' ' + status2).strip()
            elif status1_start != -1:
                status = ln_padded[status1_start:duplex_start].strip()

            # Remove any VLAN-like tokens from status (e.g., '(0002)') that may have leaked into slicing
            status = re.sub(r"\(?\d{2,}\)?", '', status).strip()

            # Fallback: split by 2+ spaces and build status from tokens (skip VLAN-like tokens)
            if not status:
                parts2 = parts
                state_tokens = [t.strip() for t in parts2[2:] if not re.match(r'^\(?\d+\)?$', t.strip()) and t.strip()]
                # keep only tokens containing letters (D, E, R, A, NP, FULL, etc.)
                state_tokens = [t for t in state_tokens if re.search(r'[A-Za-z]', t)]
                if len(state_tokens) >= 2:
                    status = (state_tokens[0] + ' ' + state_tokens[1]).strip()
                elif len(state_tokens) == 1:
                    status = state_tokens[0].strip()

            duplex_field = ln_padded[duplex_start:].strip()
            duplex = duplex_field.split()[0] if duplex_field else ''

            if not interface or not re.search(r"\d", interface):
                continue

            found_interfaces_for_device.append({
                'ip_address': ip_address,
                'expected_hostname': expected_hostname,
                'vendor': 'extreme',
                'interface': interface,
                'status': status or '',
                'description': description or '',
                'duplex': duplex or '',
                'result': 'Success'
            })
    else:
        # Fallback defensivo: split por 2+ espacios y mapear campos
        parts_pattern = re.compile(r"\s{2,}")
        for ln in lines:
            if not ln.strip() or ln.strip().startswith('====='):
                continue
            parts = parts_pattern.split(ln.strip())
            if len(parts) < 2:
                continue
            interface = parts[0].strip()
            description = parts[1].strip() if len(parts) > 1 else ''
            status = parts[2].strip() if len(parts) > 2 else ''
            duplex = parts[3].strip() if len(parts) > 3 else ''

            if not interface or not re.search(r"\d", interface):
                continue

            found_interfaces_for_device.append({
                'ip_address': ip_address,
                'expected_hostname': expected_hostname,
                'vendor': 'extreme',
                'interface': interface,
                'status': status or '',
                'description': description or '',
                'duplex': duplex or '',
                'result': 'Success'
            })

    if not found_interfaces_for_device:
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'vendor': 'extreme',
            'interface': 'N/A',
            'status': 'No interface status found',
            'description': '',
            'duplex': '',
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
                'vendor': 'huawei',
                'interface': interface,
                'status': status_phy,
                'description': description,
                'duplex': '',
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
                'duplex': '',
                'result': 'Success'
            })
    
    if not found_interfaces_for_device:
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'brand': 'huawei',
            'interface': 'N/A',
            'status': 'No interface status found',
            'description': '',
            'duplex': '',
            'result': 'No relevant interfaces'
        })
    
    with results_lock:
        results.extend(found_interfaces_for_device)

# Dictionary of functions by brand, adjust if SSH or Telnet is required
BRAND_HANDLERS = {
    'cisco': {'params': dev.cisco_ssh, 'extract_func': extract_cisco_interfaces},
#    'cisco_nexus': {'params': dev.cisco_ssh, 'extract_func': extract_cisco_nexus_interfaces}, 
    'extreme': {'params': dev.extreme_ssh, 'extract_func': extract_extreme_interfaces},
    'huawei': {'params': dev.huawei_ssh, 'extract_func': extract_huawei_interfaces}
}

def verify_device(row):
    ip_address = row['ip_address']
    expected_hostname = row.get('expected_hostname', 'N/A')
    # Defensive: handle missing or NaN vendor values coming from Excel
    vendor_raw = row.get('vendor', '')
    if pd.isna(vendor_raw):
        vendor = ''
    else:
        vendor = str(vendor_raw).strip().lower()

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
output_excel_file = './Results/status_interfaces_results.xlsx'
save_results(results, output_excel_file)

# Calculate and display the total execution time
end_time = time.time()
elapsed_time = (end_time - start_time) / 60
pprint(f'Total execution time: {elapsed_time:.2f} minutos')