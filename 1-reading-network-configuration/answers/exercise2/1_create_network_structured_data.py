# pip install --user textfsm
# pip install --user netmiko
import json
import yaml
import csv
import os
import netmiko
import ipaddress
from copy import deepcopy
from ciscoconfparse import CiscoConfParse

# Configure logging so it goes to a .log file next to this script.
import logging
this_script_dir = os.path.dirname(os.path.realpath(__file__))
log_file = f"{this_script_dir}/log/exercise2.log"
logging.basicConfig(filename=log_file, encoding='utf-8', level=logging.DEBUG, filemode="w")

# Configure a global variables to store things like
# our known BGP key.
# (Don't try this at home)
BGP_MD5_KEY = "foobar"
INPUT_FILENAME = "hosts.yaml"
OUTPUT_FILENAME = "devices.json"

# The real script
def main():

    with open("hosts.yaml") as f:
        #  This creates a list of dictionaries from a YAML file.
        #
        #  This will take the YAML file that looks similar to the following:
        #      - host: "10.0.0.1"
        #      device_type: "cisco_xr"
        #      username: "root"
        #      password: "password"
        #      - host: "10.0.0.2
        #      {...}

        #  And create a dictionary, looking like the following:
        #      [{"host": "10.0.0.1", "device_type": "cisco_xr", "username": "root", "password": "password"}, {...}]
        #
        #  We can access the IP address of the first host like so:
        #      first_host_ip = mylist[0]["host"]
        
        # YAML is convenient, and only a single line of code is required.
        hosts = yaml.safe_load(f)



    # Now we are in the meat of it. Let's look at each host.
    parsed_data = []
    for host in hosts:

        # Create the connection with our host.
        connection = netmiko.ConnectHandler(**host)

        try:
            # We need the name, ip, platform, version, BGP peers, and interfaces of our host.
            # The functions that are called to obtain these are different based on if we are
            #   on a Cisco or Juniper device. We know ahead of time which hosts are going to
            #   which OS, so we will look and then collect data based on it.
            if host["device_type"] == "cisco_xr":
                # Call each helper function from below to collect the data.
                data = {
                    "name": get_cisco_hostname(connection),
                    "ip": host["host"],
                    "platform": host["device_type"],
                    "version": get_cisco_version(connection),
                    "peers": get_cisco_bgp_peers(connection, md5_key=BGP_MD5_KEY),
                    "interfaces": get_cisco_interfaces(connection)
                }

            elif host["device_type"] == "juniper_junos":
                # Call each helper function from below to collect the data.
                data = {
                    "name": get_junos_hostname(connection),
                    "ip": host["host"],
                    "platform": host["device_type"],
                    "version": get_junos_version(connection),
                    "peers": get_junos_bgp_peers(connection, md5_key=BGP_MD5_KEY),
                    "interfaces": get_junos_interfaces(connection)
                }
            
            # If the host is neither our Cisco and Juniper OSs, then cause an error.
            else:
                raise Exception(f"Device type {host['device_type']} not recognized.")
            
            # We are done with this host, let's add it to the data.
            parsed_data.append(data)
            print(json.dumps(data, indent=4))

        # If anything wrong happens that causes an Exception, the script will move to this line.
        #   It will print out the host that we errored on, and then containue raising the exception.
        except Exception:
            print(f"Errored on host: {host}!")
            raise

        # "finally" means that we will run this line, no matter what.
        # We want to make sure we close our SSH connections whether things work, or not,
        #   otherwise, they will become stale and take up TTYs on the routers.
        finally:
            connection.disconnect()
    
    # Put our data into a file as a JSON.
    with open(OUTPUT_FILENAME, "w") as f:
        json.dump(parsed_data, f, indent=4)
    
    """ Done! """


#####
# Helper functions
#####

def get_junos_hostname(connection: netmiko.ConnectHandler):
    # Extract the hostname from running "show version | display json"
    # Juniper makes this easy since it will already be in JSON format.

    # Run the command, and convert the JSON output into a Python dictionary.
    output = json.loads(connection.send_command("show version | display json"))
    # Read the dictionary to pull out the hostname value.
    hostname = output["software-information"][0]["host-name"][0]["data"]
    return hostname


def get_junos_version(connection: netmiko.ConnectHandler):
    # Extract the version number from "show version | display json"
    # Juniper makes this easy since it will already be in JSON format.

    # Run the command, and convert the JSON output into a Python dictionary.
    output = json.loads(connection.send_command("show version | display json"))
    # Read the dictionary to pull out the version number value.
    version = output["software-information"][0]["junos-version"][0]["data"]
    return version


def get_junos_bgp_peers(connection: netmiko.ConnectHandler, md5_key=""):
    # Extract the BGP peers from running "show bgp neighbor | display json"
    # Juniper makes this easy since it will already be in JSON format.

    # Create an empty list to store our data in.
    result = []

    # Run the command, and convert the JSON output into a Python dictionary.
    bgp_data = json.loads(connection.send_command("show bgp neighbor | display json"))

    # Read the dictionary to pull out the list of BGP peers.
    list_of_peers = bgp_data["bgp-information"][0]["bgp-peer"]

    # Iterate over each peer
    for peer in list_of_peers:
        # Extract the IP and port number for each BGP peer.
        # It will look like "10.10.10.1+12345"
        peer_ip_and_port = peer["peer-address"][0]["data"]

        # Manipulate the string and get just the IP.
        ip = peer_ip_and_port.split("+")[0]

        # Add it to our "result" list that we will return at the end.
        result.append({"remote_address": ip, "md5_key": md5_key})

    return result


def get_junos_interfaces(connection: netmiko.ConnectHandler):
    # Create a detailed dictionary of all interfaces and their configuration
    #   using "show configuration interfaces | display json"
    # Juniper makes this easy since it will already be in JSON format.

    # Create an empty list to store our data in.
    result = []

    # Run the command, and convert the JSON output into a Python dictionary.
    intf_data = json.loads(
        connection.send_command("show configuration interfaces | display json")
    )

    # Drill down into the dictionary to where the interfaces really are.
    interfaces = intf_data["configuration"]["interfaces"]["interface"]
    for intf in interfaces:
        # Now we will look at each interface. The data we are looking at right now looks simiar to:
        #
        #  eth1 {
        #    description foobar;
        #    unit 0 {
        #        family inet {
        #            address 172.17.1.17/31;
        #        }
        #    }
        #    unit 100 {
        #        description foo;
        #        vlan-id 100;
        #        family inet {
        #            address 198.51.100.2/24;
        #        }
        #    }
        #    unit 200 {
        #        description foo;
        #        vlan-id 200;
        #        family inet {
        #            address 192.0.2.2/24;
        #        }
        #    }
        #
        # For each interface, add the name and description (if it exists) to our own result.
        #  Also add an empty list for subinterfaces, which we will populate next.
        data = {
            "name": intf["name"],
            "description": intf["description"] if "description" in intf.keys() else "",
            "sub_ints": [],
        }
        # Drill down more into the interface and look at its subinterfaces.
        for sub_int in intf["unit"]:
            # Create the "full name" based off the unit number that we see.
            #   Ex. "100" becomes "eth1.100"
            name = f"{intf['name']}.{sub_int['name']}"

            # Add the description to our subinterface data, if it exists.
            description = (
                sub_int["description"] if "description" in sub_int.keys() else ""
            )
            # Add the vlan id to our subinterface data, if it exists.
            vlan_id = sub_int["vlan-id"] if "vlan-id" in sub_int.keys() else ""

            # Now, extract the IP address
            # We will assume there is only a single IPv4 address configured.
            addr = sub_int["family"]["inet"]["address"][0]["name"]

            # Use Python's ipaddress module to read our string into a sophisticated
            #   IPv4_Interface object. This lets us do cool things.
            addr = ipaddress.ip_interface(addr)

            # The cool thing we do: It automatically converts our /24 to 255.255.255.0.
            #   (We won't code the conversions ourself, that's what this is for)
            ip, mask = addr.with_netmask.split("/")

            # If the unit is 0, add our collected data to the top-level interface (ex. eth1).
            # We do this instead of adding it as "eth1.0" to the subinterfaces.
            # This keeps our behavior consistent among different vendors.
            if str(name) == "0":
                data.update({"ip_address": ip, "subnet_mask": mask, "vlan": vlan_id})
            
            # If it isn't unit 0, then add a subinterface to our list.
            else:
                data["sub_ints"].append(
                    {
                        "name": name,
                        "description": description,
                        "vlan": vlan_id,
                        "ip_address": ip,
                        "subnet_mask": mask,
                    }
                )
        # Add all data about this interface into our result to send later.
        # Then, move to the next interface.
        result.append(data)

    return result


def get_cisco_hostname(connection: netmiko.ConnectHandler):
    # Run "show run hostname" and collect the output.
    output = connection.send_command("show run hostname")

    # Ex. Turn "hostname cisco1" into "cisco1" and return.
    return output.split()[-1]


def get_cisco_version(connection: netmiko.ConnectHandler):
    # Run "show version | i ^ Version" and collect the output.
    output = connection.send_command("show version | i ^ Version")

    # Ex. Turn the outputted " Version      : 7.9.1" into "7.9.1" and return.
    return output.split()[-1]


def get_cisco_bgp_peers(connection: netmiko.ConnectHandler, md5_key=""):
    # Run "show ip bgp summary" and get the IPs of all peers.
    command = "show ip bgp summary"

    # Create an empty list to store our data.
    result = []

    # Send our command and get the output.
    # Our output will be pre-formatted because are turning TextFSM on.
    # TextFSM understands what the output on th router will look like, since
    #   we are running a command it supports.
    bgp_neighbors = connection.send_command(command, use_textfsm=True)

    for peer in bgp_neighbors:
        # Add the IP addresses to our data that we're collecting.
        try:
            result.append({"remote_address": peer["bgp_neigh"], "md5_key": md5_key})
        
        # If BGP is not running, the router will print something like, 
        #   "% BGP instance 'default' not active"
        # Netmiko sees "% " and knows an error happened.
        # Catch this error so we can choose just to log and ignore this device.
        except TypeError:
            # This 'replace' turns the carriage returns in the raw output into a single-lined string.
            #   We don't want that in our logs.
            flattened_output = bgp_neighbors.replace('\n', '\\n')
            logging.info(f"Cannot format output for \"{command}\". BGP may not be running? Raw output:{flattened_output}")
            return []
    return result


def get_cisco_interfaces(connection: netmiko.ConnectHandler):
    # For interface configuration on Cisco devices, we can use the "ciscoconfparse" module, since
    #   TextFSM doesn't support our command.
    # 
    # We can search and extract blocks of configuration like this, getting only the interfaces
    #   we care about by using the right CiscoConfParse functions.
    #
    #    interface GigabitEthernet0/0/0/1.100
    #        description bar to foo
    #        ipv4 address 198.51.100.1 255.255.255.0
    #        encapsulation dot1q 100
    #    !
    #    
    # After cleaning up the output (like removing extra spaces), we can format like so:
    #
    #   {
    #       "name": "Gi0/0/0/1",
    #       "description": "Some customer connects here!",
    #       "vlan": "100",
    #       "ip_address": "10.0.0.1",
    #       "subnet_mask": "255.255.255.0"
    #   }    

    # Create an empty dictionary to store our interfaces as we discover them.
    interfaces = {}

    # Create an empty list to store subinterfaces as we discover them, and we'll
    #   nest them in the appropriate parent interfaces later.
    sub_interfaces = []

    # Get the output for "show run". This will be raw and unformatted.
    cisco_config = connection.send_command("show run")

    # Turn this giant singular string of output into a list of lines.
    parser = CiscoConfParse(cisco_config.split("\n"))

    # parser.find_objects('^interface .*') will automatically make a list of all
    #   lines that start with "interface " that we can iterate over.
    #   It's also nice because it stores that interface's configuration with it.
    for intf in parser.find_objects('^interface .*'):

        # Get the name by converting "interface GigabitEthernet0/1" to "GigabitEthernet0/1".
        intf_name = intf.text.split()[-1]

        # Find the "description" line, and extract. Ex. Turn "description hello!" into "hello!"
        intf_description = intf.re_search_children("^ description ")
        if intf_description:
            tmp = intf_description[0].text.strip()
            intf_description = " ".join(tmp.split()[1:])
        else:
            # If description doesn't exist, just use an empty string.
            intf_description = ""

        # Extract the vlan id. Ex. turn "encapsulation dot1q 100" into "100".
        intf_vlan = intf.re_search_children("^ encapsulation dot1q ")
        intf_vlan = intf_vlan[0].text.split()[-1] if intf_vlan else ""

        # Extract the IP address and mask.
        #   Ex. Turn "ipv4 address 10.10.10.1 255.255.255.0" into two separate stringsm
        #   one in our 'ip' variable and the other in our 'mask' variable.
        raw_ipmask = intf.re_search_children("^ ipv4 address ")
        ip, mask = raw_ipmask[0].text.split()[-2] if raw_ipmask else "", ""

        # Take all the interface config we collected and put it into a nicely-formatted dictionary.
        data = {
            "name": intf_name,
            "description": intf_description,
            "vlan": intf_vlan,
            "ip_address": ip,
            "subnet_mask": mask
        }
        
        # If it's a subinterface, put in the 'sub_interfaces' list to store later.
        if "." in intf_name:
            sub_interfaces.append(data)
        # Otherwise, put it in our top-most 'interfaces' dictionary.
        else:
            data["sub_ints"] = []
            interfaces[intf_name] = data
    
    # Finally we are done going through our interfaces.
    # Lets go back and sort all our subinterfaces into their parents.
    for i in sub_interfaces:
        parent_intf = i["name"].split(".")[0]
        interfaces[parent_intf]["sub_ints"].append(i)

    # Return our interfaces.
    return list(interfaces.values())

if __name__ == "__main__":
    main()

