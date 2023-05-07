#!/usr/bin/python

import json
import yaml

f = open('output.json')

data = json.load(f)

f.close()

inventory = {'all': {'vars': {'ansible_user': 'clab'}, 'children': {'junos': {'hosts': {}, 'vars': {'ansible_ssh_pass': 'clab123'}},
                                                                  'iosxr': {'hosts':{}, 'vars': {'ansible_network_os': 'iosxr',
                                                                                                 'ansible_ssh_pass': 'clab@123',
                                                                                                 'ansible_connection': 'ansible.netcommon.network_cli'}}}}}

for host in data:
    if(host['platform'] == 'juniper_junos'):
        inventory['all']['children']['junos']['hosts'][host['name']] = {'ansible_host': host['ip'], 'device_type': 'JUNOS' }
    elif(host['platform'] == 'cisco_xr'):
        inventory['all']['children']['iosxr']['hosts'][host['name']] = {'ansible_host': host['ip'], 'device_type': 'IOSXR'}
    else:
        inventory['all']['hosts'][host['name']] = {'ansible_host': host['ip']}

with open('inventory.yaml', 'w') as file:
    yaml.dump(inventory, file)
