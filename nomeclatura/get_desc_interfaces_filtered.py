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
        raise ValueError("La columna 'vendor' no se encontró en el archivo Excel.")
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

# Function to extract interfaces with MPLS/INET/P2P from Cisco devices (IOS/IOS-XE)
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
        f"show interface description | include MPLS|INET|P2P",
        expect_string=current_prompt,
        read_timeout=180
    )
    
    pattern = re.compile(
        r"^(?P<interface>\S+)\s+(?P<status>admin down|down|up)\s+(?:\S+)\s+(?P<description>.*(?:MPLS|INET|P2P).*)$",
        re.MULTILINE
    )
    
    found_interfaces_for_device = []
    matches = pattern.finditer(output_interfaces)
    for match in matches:
        interface = match.group("interface").strip()
        status = match.group("status").strip()
        description = match.group("description").strip()
        
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'vendor': 'cisco',
            'interface': interface,
            'status': status,
            'description': description,
            'result': 'Success'
        })
    
    if not found_interfaces_for_device:
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'vendor': 'cisco',
            'interface': 'N/A',
            'status': 'N/A',
            'description': 'No interfaces with MPLS | INET | P2P found',
            'result': 'No relevant interfaces'
        })
    
    with results_lock:
        results.extend(found_interfaces_for_device)

# Function to extract interfaces with MPLS/INT/P2P from Cisco Nexus devices
def extract_cisco_nexus_interfaces(net_connect, ip_address, expected_hostname, results, results_lock):
    current_prompt = net_connect.find_prompt()
    
    output_interfaces_raw = net_connect.send_command(
        f"show interface description | include MPLS|INET|P2P",
        expect_string=current_prompt,
        read_timeout=180
    )

    relevant_lines = [
        line for line in output_interfaces_raw.splitlines() 
        if "MPLS" in line or "INET" in line or "P2P" in line
    ]
    output_interfaces_filtered = "\n".join(relevant_lines)

    pattern = re.compile(
        r"^(?P<interface>\S+)\s+\S+\s+(?P<speed>\S+)+\s+(?P<description>.*(?:MPLS|INET|P2P).*)$",
        re.MULTILINE
    )
    
    found_interfaces_for_device = []
    matches = pattern.finditer(output_interfaces_filtered)
    for match in matches:
        interface = match.group("interface").strip()
        description = match.group("description").strip()
        status = match.group("speed").strip()
        
        #status = "N/A (from description)" # Status is not directly available from this command on Nexus
        
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'vendor': 'cisco',
            'interface': interface,
            'status': status,
            'description': description,
            'result': 'Success'
        })
    
    if not found_interfaces_for_device:
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'vendor': 'cisco',
            'interface': 'N/A',
            'status': 'N/A',
            'description': 'No interfaces with MPLS | INET | P2P found (Cisco Nexus)',
            'result': 'No relevant interfaces'
        })
    
    with results_lock:
        results.extend(found_interfaces_for_device)

# Function to extract interfaces with MPLS/INET/P2P from Extreme devices
def extract_extreme_interfaces(net_connect, ip_address, expected_hostname, results, results_lock):
    """Extract interfaces with MPLS/INET/P2P from Extreme devices."""
    prompt_pattern = rf"({re.escape(expected_hostname)})\.\d+\s*#\s*"
    output_interfaces = net_connect.send_command(
        f"show port no-refresh ",
        expect_string=prompt_pattern,
        read_timeout=180
    )

    # Pattern to match desired keywords in the display/description
    token_pattern = re.compile(r"(MPLS|INET|P2P|MOV|MVS|CLR|ENT|CIR|IFX|GTD)", re.IGNORECASE)
    
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
                if len(parts) > 1:
                        desc_candidate = parts[1].strip()
                        # reject VLAN-like tokens, common 'none' values and short uppercase single/two-letter status tokens
                        if desc_candidate and re.search(r'[A-Za-z]', desc_candidate) and not re.match(r'^\(?\d+\)?$', desc_candidate) and desc_candidate.lower() not in ('default', 'none', 'n/a') and not re.fullmatch(r'[A-Z]{1,2}', desc_candidate):
                            description = desc_candidate
                        else:
                            description = ''
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
                # If description was empty, state tokens may start at index 1, otherwise at index 2
                start_idx = 1 if not description else 2
                candidate_tokens = parts2[start_idx:]
                state_tokens = [t.strip() for t in candidate_tokens if not re.match(r'^\(?\d+\)?$', t.strip()) and t.strip()]
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
            # Only keep entries whose description contains one of the desired tokens
            if not description or not token_pattern.search(description):
                continue

            found_interfaces_for_device.append({
                'ip_address': ip_address,
                'expected_hostname': expected_hostname,
                'vendor': 'extreme',
                'interface': interface,
                'status': status or '',
                'description': description,
                'result': 'Success'
            })
    else:
        # Fallback: try regex per line
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
            # Filter fallback entries by tokens as well
            if not description or not token_pattern.search(description):
                continue

            found_interfaces_for_device.append({
                'ip_address': ip_address,
                'expected_hostname': expected_hostname,
                'vendor': 'extreme',
                'interface': interface,
                'status': status or '',
                'description': description,
                'result': 'Success'
            })

    if not found_interfaces_for_device:
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'vendor': 'extreme',
            'interface': '',
            'status': '',
            'description': 'No interfaces description found',
            'result': 'No relevant interfaces'
        })
    
    with results_lock:
        results.extend(found_interfaces_for_device)

# Function to extract interfaces with MPLS/INT from Huawei devices
def extract_huawei_interfaces(net_connect, ip_address, expected_hostname, results, results_lock):
    current_prompt = net_connect.find_prompt()
    output_interfaces = net_connect.send_command(
        f"display interface description | include MPLS|INET|P2P",
        expect_string=current_prompt,
        read_timeout=180
    )

    lines = output_interfaces.splitlines()
    header_idx = None
    for i, ln in enumerate(lines):
        if 'Interface' in ln and 'PHY' in ln and 'Protocol' in ln:
            header_idx = i
            break

    pattern = re.compile(
        r"^(?P<interface>\S+)\s+(?P<status_phy>\S+)\s+(?:\S+)\s+(?P<description>.*)$",
        re.MULTILINE
    )

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
                'vendor': 'huawei',
                'interface': interface,
                'status': status_phy,
                'description': description,
                'result': 'Success'
            })
    
    if not found_interfaces_for_device:
        found_interfaces_for_device.append({
            'ip_address': ip_address,
            'expected_hostname': expected_hostname,
            'vendor': 'huawei',
            'interface': 'N/A',
            'status': 'N/A',
            'description': 'N/A',
            'result': 'No relevant interfaces with MPLS | INET | P2P found'
        })
    
    with results_lock:
        results.extend(found_interfaces_for_device)

# Dictionary of functions by brand; adjust if SSH or Telnet is required
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
        handle_exceptions(ip_address, expected_hostname, vendor, f"Vendor '{vendor}' no soportado", results, results_lock)
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
output_excel_file = './Results/filtered_interfaces_summary.xlsx'
save_results(results, output_excel_file)

# Calculate and display total execution time
end_time = time.time()
elapsed_time = (end_time - start_time) / 60
pprint(f'Tiempo total de ejecución: {elapsed_time:.2f} minutos')