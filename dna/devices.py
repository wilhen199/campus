from dotenv import load_dotenv
import os
load_dotenv()

cisco_ssh = {
	'device_type': 'cisco_ios',
  'username': os.getenv('user'),
  'password': os.getenv('password'),
  'secret': os.getenv('password'),  
  'timeout': 180
	}

cisco_telnet = {
	'device_type': 'cisco_ios_telnet',
  'username': os.getenv('user'),
  'password': os.getenv('password'),
  'secret': os.getenv('password'),  
  'timeout': 180
	}

extreme_ssh = {
	'device_type': 'extreme',
  'username': os.getenv('user'),
  'password': os.getenv('password'),
  'secret': os.getenv('password'),  
}

extreme_telnet = {
	'device_type': 'extreme_telnet',
  'username': os.getenv('user'),
  'password': os.getenv('password'),
  'secret': os.getenv('password'),    
  'timeout': 180
}

huawei_ssh = {
	'device_type': 'huawei',
  'username': os.getenv('user'),
  'password': os.getenv('password'),
  'secret': os.getenv('password'),  
  'timeout': 180
}
