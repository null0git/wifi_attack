import os

def scan_connected_devices(target_ip_range):
    devices = []
    result = os.popen(f"nmap -sn {target_ip_range}").read()
    for line in result.splitlines():
        if 'Nmap scan report for' in line:
            ip = line.split(' ')[-1]
            mac = 'Unknown'
            manufacturer = 'Unknown'
            devices.append({'ip': ip, 'mac': mac, 'manufacturer': manufacturer})
    return devices
