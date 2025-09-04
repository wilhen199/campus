import concurrent.futures as cf
import threading
import pandas as pd
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
import devices as dev
from rich.pretty import pprint
import time

# List to store results
results = []
results_lock = threading.Lock()

# Read data from the xlsx file using pandas
try:
    df = pd.read_excel('./Files/isis.xlsx','Hoja1')
except FileNotFoundError:
    pprint("Error: The file './Files/isis.xlsx' was not found.")
    exit()

# Save results
def save_results_to_excel(data, output_file):
    # Headers for saving results to an Excel file:
    header = ['ip_address', 'expected_hostname', 'prompt', 'result']  # Define the file header
    # Create a DataFrame with the results
    df_result = pd.DataFrame(data, columns=header)
    df_result.to_excel(output_file, index=False)
    pprint(f'Results saved in {output_file}')

# Common connection parameters for netmiko (adjust as needed)
device_params = dev.cisco_ssh
#device_params = dev.cisco_telnet



def verify_device(row):
    ip_address = row['ip_address']
    expected_hostname = row.get('expected_hostname')  # Get expected hostname if available
    result = f"{ip_address},{expected_hostname},,Error: Unexpected output"  # Initialize result

    # Update device parameters with current IP
    device_params_local = device_params.copy()
    device_params_local['host'] = ip_address

        # Save SSH logs
    output_logs = f"./session_logs/session_log_{ip_address}.log"
    device_params_local['session_log'] = output_logs
    
    pprint(f"Connecting to {ip_address}...")
    try:
        with ConnectHandler(**device_params_local) as net_connect:
            # Enter enable mode
            net_connect.enable()
            current_prompt = net_connect.find_prompt()
            
            # Get current device configuration
            output = net_connect.send_command("show running-config | include isis", expect_string=current_prompt, read_timeout=180)
            print(output)
            if output == "":
                result = f"{ip_address},{expected_hostname},{current_prompt},feature isis no habilitado"

            result = f"{ip_address},{expected_hostname},{current_prompt},{output}"

    except NetMikoTimeoutException:
        print(f"Timeout connecting to {ip_address}")
        result = f"{ip_address},{expected_hostname},,Error: Timeout"
    except NetMikoAuthenticationException:
        print(f"Authentication failed connecting to {ip_address}")
        result = f"{ip_address},{expected_hostname},,Error: Authentication failed"
    except (SSHException):
        print (f'SSH might not be enabled: {ip_address}')
        result = f"{ip_address},{expected_hostname},,Error: SSH connection failed"
    except Exception as err:
        print(f"Error connecting to {ip_address}: {err}")
        result = f"{ip_address},{expected_hostname},,Error: General {err}"
    with results_lock:
        results.append(result)

## Create a ThreadPoolExecutor to manage threads
#with cf.ThreadPoolExecutor() as executor:
#    futures = [executor.submit(verify_device, row) for index, row in df.iterrows()]
#
#    # Ensure all threads have completed
#    for future in cf.as_completed(futures):
#        future.result()


if __name__ == "__main__":
    start_time = time.time()
    pprint("Starting ISIS configuration retrieval process...")
    # Create a ThreadPoolExecutor to manage threads
    with cf.ThreadPoolExecutor() as executor:
        futures = [executor.submit(verify_device, row) for index, row in df.iterrows()]

        # Ensure all threads have completed
        for future in cf.as_completed(futures):
            future.result()

    data = []
    for result in results:
        fields = result.split(',', 3)
        data.append(fields)

    # Output Excel file path
    output_file = './Results/get_isis_results.xlsx'
    
    save_results_to_excel(data, output_file)
    elapsed_time = (time.time() - start_time) / 60
    pprint(f"Process completed in {elapsed_time:.2f} minutes.")