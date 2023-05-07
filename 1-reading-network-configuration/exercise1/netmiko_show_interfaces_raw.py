from netmiko import Netmiko

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
    ip=host
  )

  # Send a command to the router, and get back the raw output
  raw_output = connection.send_command(command_to_run)
  
  # The "really raw" output has '\n' characters appear instead of a real carriage return.
  # Converting them into carriage returns will make it a little more readable for this demo.
  raw_output = raw_output.replace("\\n", "\n")

  print(
    f"### This is the raw output from {host}, without any parsing: ###\n",
    raw_output + "\n"
  )
