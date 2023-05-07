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
OUTPUT_FILENAME = "devices.json"

# The real script
def main():

    with open("./hosts.yaml") as f:
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

        connection = netmiko.ConnectHandler(**host)

        try:
            if host["device_type"] == "cisco_xr":
                data = {
                    "name": get_cisco_hostname(connection),
                    "ip": host["host"],
                    "platform": host["device_type"],
                    "version": get_cisco_version(connection),
                    "peers": get_cisco_bgp_peers(connection, md5_key=BGP_MD5_KEY),
                    "interfaces": get_cisco_interfaces(connection)
                }

            elif host["device_type"] == "juniper_junos":
                data = {
                    "name": get_junos_hostname(connection),
                    "ip": host["host"],
                    "platform": host["device_type"],
                    "version": get_junos_version(connection),
                    "peers": get_junos_bgp_peers(connection, md5_key=BGP_MD5_KEY),
                    "interfaces": get_junos_interfaces(connection)
                }
            

            else:
                raise Exception(f"Device type {host['device_type']} not recognized.")
            
            parsed_data.append(data)
            print(json.dumps(data, indent=4))

        except Exception:
            print(f"Errored on host: {host}!")
            raise

        finally:
            connection.disconnect()
        
    with open(OUTPUT_FILENAME, "w") as f:
        json.dump(parsed_data, f, indent=4)
    
    """ Done! """


#####
# Helper functions
#####

def get_junos_hostname(connection: netmiko.ConnectHandler):
    output = json.loads(connection.send_command("show version | display json"))
    hostname = output["software-information"][0]["host-name"][0]["data"]
    return hostname


def get_junos_version(connection: netmiko.ConnectHandler):
    output = json.loads(connection.send_command("show version | display json"))
    version = output["software-information"][0]["junos-version"][0]["data"]
    return version


def get_junos_bgp_peers(connection: netmiko.ConnectHandler, md5_key=""):
    result = []
    bgp_data = json.loads(connection.send_command("show bgp neighbor | display json"))

    list_of_peers = bgp_data["bgp-information"][0]["bgp-peer"]

    for peer in list_of_peers:
        peer_ip_and_port = peer["peer-address"][0]["data"]
        ip = peer_ip_and_port.split("+")[0]
        result.append({"remote_address": ip, "md5_key": md5_key})

    return result


def get_junos_interfaces(connection: netmiko.ConnectHandler):
    result = []
    intf_data = json.loads(
        connection.send_command("show configuration interfaces | display json")
    )
    interfaces = intf_data["configuration"]["interfaces"]["interface"]
    for intf in interfaces:
        data = {
            "name": intf["name"],
            "description": intf["description"] if "description" in intf.keys() else "",
            "sub_ints": [],
        }
        for sub_int in intf["unit"]:
            name = f"{intf['name']}.{sub_int['name']}"
            description = (
                sub_int["description"] if "description" in sub_int.keys() else ""
            )
            vlan_id = sub_int["vlan-id"] if "vlan-id" in sub_int.keys() else ""

            # We will assume there is only a single IPv4 address configured.
            addr = sub_int["family"]["inet"]["address"][0]["name"]
            addr = ipaddress.ip_interface(addr)
            ip, mask = addr.with_netmask.split("/")

            if str(name) == "0":
                data.update({"ip_address": ip, "subnet_mask": mask, "vlan": vlan_id})
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
        result.append(data)

    return result


def get_cisco_hostname(connection: netmiko.ConnectHandler):
    output = connection.send_command("show run hostname").split()[-1]
    return output


def get_cisco_version(connection: netmiko.ConnectHandler):
    output = connection.send_command("show version | i ^ Version")
    return output.split()[-1]


def get_cisco_bgp_peers(connection: netmiko.ConnectHandler, md5_key=""):
    command = "show ip bgp summary"
    result = []
    bgp_neighbors = connection.send_command(command, use_textfsm=True)

    for peer in bgp_neighbors:
        try:
            result.append({"remote_address": peer["bgp_neigh"], "md5_key": md5_key})
        except TypeError:
            # This error can occur if the router returns something like: 
            # "% BGP instance 'default' not active"
            flattened_output = bgp_neighbors.replace('\n', '\\n')
            logging.info(f"Cannot format output for \"{command}\". BGP may not be running? Raw output:{flattened_output}")
            return []
    return result


def get_cisco_interfaces(connection: netmiko.ConnectHandler):
    """
    For interface configuration on Cisco devices, we can use the "ciscoconfparse" module.

    We can search and extract blocks of configuration like this, getting only the interfaces
    we care about by using the right CiscoConfParse functions.

        interface GigabitEthernet0/0/0/1.100
            description bar to foo
            ipv4 address 198.51.100.1 255.255.255.0
            encapsulation dot1q 100
        !
        
    After cleaning up the output (like removing extra spaces), we can format like so:

    {
        "name": "Gi0/0/0/1",
        "description": "Some customer connects here!",
        "vlan": "100",
        "ip_address": "10.0.0.1",
        "subnet_mask": "255.255.255.0"
    }    

    """
    interfaces = {}
    sub_interfaces = []
    cisco_config = connection.send_command("show run")
    parser = CiscoConfParse(cisco_config.split("\n"))

    for intf in parser.find_objects('^interface .*'):
        intf_name = intf.text.split()[-1]

        intf_description = intf.re_search_children("^ description ")
        if intf_description:
            tmp = intf_description[0].text.strip()
            intf_description = " ".join(tmp.split()[1:])
        else:
            intf_description = ""

        intf_vlan = intf.re_search_children("^ encapsulation dot1q ")
        intf_vlan = intf_vlan[0].text.split()[-1] if intf_vlan else ""

        raw_ipmask = intf.re_search_children("^ ipv4 address ")
        ip, mask = raw_ipmask[0].text.split()[-2] if raw_ipmask else "", ""

        data = {
            "name": intf_name,
            "description": intf_description,
            "vlan": intf_vlan,
            "ip_address": ip,
            "subnet_mask": mask
        }
        
        if "." in intf_name:
            sub_interfaces.append(data)
        else:
            data["sub_ints"] = []
            interfaces[intf_name] = data
    
    for i in sub_interfaces:
        parent_intf = i["name"].split(".")[0]
        interfaces[parent_intf]["sub_ints"].append(i)

    return list(interfaces.values())

if __name__ == "__main__":
    main()

