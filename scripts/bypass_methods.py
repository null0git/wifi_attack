import os

def arp_spoof_bypass(interface='eth0'):
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("IP forwarding enabled to bypass ARP spoofing defenses.")

def disable_mac_filtering(interface='wlan0'):
    # Disable MAC address filtering by changing MAC address to an allowed one
    allowed_mac = '00:11:22:33:44:55'  # Replace with a valid MAC address allowed by the network
    os.system(f"ifconfig {interface} down")
    os.system(f"ifconfig {interface} hw ether {allowed_mac}")
    os.system(f"ifconfig {interface} up")
    print(f"MAC address for {interface} changed to {allowed_mac}.")
