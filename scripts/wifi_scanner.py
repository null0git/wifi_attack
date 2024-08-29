from scapy.all import *

def scan_wifi_networks(interface='wlan0'):
    networks = []
    
    def sniff_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode('utf-8')
            bssid = pkt[Dot11].addr2
            networks.append({'ssid': ssid, 'bssid': bssid})
    
    sniff(iface=interface, prn=sniff_handler, timeout=10)
    return networks
