# Exercise 2: Structured Data and Scraping the Network


### How to Complete

To complete this exercise, all TODOs must be completed in both scripts and one input YAML:
- 1_create_network_structured_data.py
- 2_add_customers_to_interfaces.py
- hosts.yaml

If done successfully, both scripts can be run in sequential order. They will output results as they run.

```
From the 2023-workshop-automation folder:

cd 1-reading-network-configuration/exercise2
python 1_create_network_structured_data.py
python 2_add_customers_to_interfaces.py
```


### Answer

The new `answers.json` will match the following, where {{x}} is your lab number:

```
[
    {
        "name": "cisco1",
        "ip": "172.16.{{x}}.2",
        "platform": "cisco_xr",
        "version": "7.9.1",
        "peers": [
            {
                "remote_address": "198.51.100.2",
                "md5_key": "foobar"
            }
        ],
        "interfaces": [
            {
                "name": "Loopback1",
                "description": "PEER_A_NETWORK",
                "vlan": "",
                "ip_address": "10.0.1.1",
                "subnet_mask": "",
                "sub_ints": [],
                "customer": "Acme Corporation"
            },
            {
                "name": "MgmtEth0/RP0/CPU0/0",
                "description": "",
                "vlan": "",
                "ip_address": "172.16.{{x}}.2",
                "subnet_mask": "",
                "sub_ints": [],
                "customer": "Beta Industries"
            },
            {
                "name": "GigabitEthernet0/0/0/0",
                "description": "NOT_IN_USE",
                "vlan": "",
                "ip_address": "",
                "subnet_mask": "",
                "sub_ints": [],
                "customer": "Gamma Enterprises"
            },
            {
                "name": "GigabitEthernet0/0/0/1",
                "description": "foobar",
                "vlan": "",
                "ip_address": "172.17.1.16",
                "subnet_mask": "",
                "sub_ints": [
                    {
                        "name": "GigabitEthernet0/0/0/1.100",
                        "description": "bar to foo",
                        "vlan": "100",
                        "ip_address": "198.51.100.1",
                        "subnet_mask": "",
                        "customer": "Epsilon Electronics"
                    },
                    {
                        "name": "GigabitEthernet0/0/0/1.200",
                        "description": "foo to biz",
                        "vlan": "200",
                        "ip_address": "192.0.2.1",
                        "subnet_mask": "",
                        "customer": "Zeta Zoological"
                    }
                ],
                "customer": "Delta Dynamics"
            },
            {
                "name": "GigabitEthernet0/0/0/2",
                "description": "NOT_IN_USE",
                "vlan": "",
                "ip_address": "",
                "subnet_mask": "",
                "sub_ints": [],
                "customer": "Eta Enterprises"
            }
        ]
    },
    {
        "name": "cisco2",
        "ip": "172.16.{{x}}.3",
        "platform": "cisco_xr",
        "version": "7.9.1",
        "peers": [],
        "interfaces": [
            {
                "name": "MgmtEth0/RP0/CPU0/0",
                "description": "",
                "vlan": "",
                "ip_address": "172.16.{{x}}.3",
                "subnet_mask": "",
                "sub_ints": []
            },
            {
                "name": "GigabitEthernet0/0/0/0",
                "description": "",
                "vlan": "",
                "ip_address": "",
                "subnet_mask": "",
                "sub_ints": []
            },
            {
                "name": "GigabitEthernet0/0/0/1",
                "description": "",
                "vlan": "",
                "ip_address": "",
                "subnet_mask": "",
                "sub_ints": []
            },
            {
                "name": "GigabitEthernet0/0/0/2",
                "description": "",
                "vlan": "",
                "ip_address": "",
                "subnet_mask": "",
                "sub_ints": []
            }
        ]
    },
    {
        "name": "juniper1",
        "ip": "172.16.{{x}}.4",
        "platform": "juniper_junos",
        "version": "23.1R1.8",
        "peers": [
            {
                "remote_address": "198.51.100.1",
                "md5_key": "foobar"
            }
        ],
        "interfaces": [
            {
                "name": "eth1",
                "description": "foobar",
                "sub_ints": [
                    {
                        "name": "eth1.0",
                        "description": "",
                        "vlan": "",
                        "ip_address": "172.17.1.17",
                        "subnet_mask": "255.255.255.254",
                        "customer": "Theta Technologies"
                    },
                    {
                        "name": "eth1.100",
                        "description": "foo",
                        "vlan": 100,
                        "ip_address": "198.51.100.2",
                        "subnet_mask": "255.255.255.0",
                        "customer": "Iota Innovations"
                    },
                    {
                        "name": "eth1.200",
                        "description": "foo",
                        "vlan": 200,
                        "ip_address": "192.0.2.2",
                        "subnet_mask": "255.255.255.0",
                        "customer": "Kappa Kinetics"
                    }
                ]
            },
            {
                "name": "eth2",
                "description": "",
                "sub_ints": [
                    {
                        "name": "eth2.0",
                        "description": "EXAMPLE_NETWORK",
                        "vlan": "",
                        "ip_address": "10.0.2.1",
                        "subnet_mask": "255.255.255.0",
                        "customer": "Lambda Labs"
                    }
                ]
            }
        ]
    }
]
```

