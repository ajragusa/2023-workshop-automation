import csv
import json

# Configure a global variables to store certain things.
# (Don't try this at home)
DEVICES_FILENAME = "devices.json"
CUSTOMERS_FILENAME = "customer_interfaces.csv"
OUTPUT_FILENAME = "answer.json"

def main():
    with open(DEVICES_FILENAME) as f:
        #  First, let's read in our previous data from JSON to a Python Dictionary.
        devices = json.load(f)
        if not devices:
            raise ValueError(f"File {DEVICES_FILENAME} is empty!")


    with open(CUSTOMERS_FILENAME) as f:
        #  Next, we'll read in our customer data.
        #
        #  This creates a list containing dictionaries.
        #  This will take a line like the following:
        #      cisco1,Gi0/0/0/1.100,Acme Co.
        #
        #  And add it to the a list, which will look like:
        #      [{"device": "cisco1", "interface": "Gi0/0/0/1.100", "customer": "Acme Co."}, {...}]
        #
        #  We can access the customer of the first interface like so:
        #      some_customer = mylist[0]["customer"]

        # Create an empty list where we can store the rows we read.
        customer_interfaces = []

        # The csv.DictReader reader will automatically associate each row 
        # with the CSV headers, like "customer" or "device". 
        csv_reader = csv.DictReader(f)
        for row in csv_reader:
            customer_interfaces.append(row)
        
        if not customer_interfaces:
            raise ValueError(f"File {CUSTOMERS_FILENAME} is empty!")
    

    #  Now that we have both our device data and customer data,
    #      let's blend the data together.
    for row in customer_interfaces:
        device_dict = find_device(devices, row["device"])
        interface_dict = find_interface(device_dict, row["interface"])
        interface_dict["customer"] = row["customer"]
    

    #  We've now added customer names to each of our interfaces.
    #  Let's print our new data for good measure, and then store it
    #      in our new file.
    print(json.dumps(devices, indent=4))
    with open(OUTPUT_FILENAME, "w") as f:
        json.dump(devices, f, indent=4)
    

    """ Done! """


#####
# Helper functions
#####

def find_device(devices, device_name):
    for device in devices:
        # If the name matches, the device was found. Return.
        if device["name"] == device_name:
            return device
    
    raise ValueError(f"Could not find device {device_name}!")

def find_interface(device, interface_name):

    is_sub_int = False
    if "." in interface_name:
        is_sub_int = True

    for intf in device["interfaces"]:
        # If we know it is a sub interface, then we know
        # we need to go deeper.
        if is_sub_int:
            for sub_int in intf["sub_ints"]:
                if interface_name == sub_int["name"]:
                    return sub_int
        
        # If it isn't a sub interface, stay at the top.
        else:
            if interface_name == intf["name"]:
                return intf
    
    raise ValueError(
        f"Could not find interface {interface_name} on device {device}!"
    )




if __name__ == "__main__":
    main()