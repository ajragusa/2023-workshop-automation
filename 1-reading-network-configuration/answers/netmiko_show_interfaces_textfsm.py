# pip install --user textfsm
# pip install --user netmiko
from netmiko import Netmiko
from pprint import pprint

username = "clab"
password = "clab@123"
device_type = "cisco_xr"
hosts = ["172.16.1.2", "172.16.1.3"]
command_to_run = "show int brief"

for host in hosts:
  # Create a variable that represents an SSH connection to our router.
  connection = Netmiko(
    username=username,
    password=password,
    device_type=device_type,
    ip=host,
  )

  # Send a command to the router, and get back the output formatted by textfsm.
  formatted_output = connection.send_command(command_to_run, use_textfsm=True)
  
  print(f"### This is the formatted output from {host}: ###")
  pprint(formatted_output)
  print("\n") # Add extra space between our outputs for each host
