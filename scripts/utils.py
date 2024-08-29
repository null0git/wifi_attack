import os

def change_mac_address(interface, new_mac):
    os.system(f"ifconfig {interface} down")
    os.system(f"ifconfig {interface} hw ether {new_mac}")
    os.system(f"ifconfig {interface} up")
    print(f"MAC address for {interface} changed to {new_mac}.")
