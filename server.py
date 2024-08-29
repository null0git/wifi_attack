from flask import Flask, render_template, jsonify, request
from scripts.wifi_scanner import scan_wifi_networks
from scripts.device_scanner import scan_connected_devices
from scripts.wifi_attacks import (
    perform_deauth_attack, perform_handshake_capture, perform_evil_twin_attack,
    perform_wps_bruteforce, perform_karma_attack
)
from scripts.mitm_attacks import (
    perform_mitm_attack, perform_dhcp_spoofing, perform_ssl_stripping, perform_dns_spoofing
)
from scripts.bypass_methods import arp_spoof_bypass, disable_mac_filtering
from scripts.utils import change_mac_address
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan_wifi', methods=['GET'])
def scan_wifi():
    networks = scan_wifi_networks()
    return jsonify(networks)

@app.route('/scan_devices', methods=['GET'])
def scan_devices():
    target_ip_range = request.args.get('target_ip_range')
    devices = scan_connected_devices(target_ip_range)
    return jsonify(devices)

@app.route('/perform_attack', methods=['POST'])
def attack():
    attack_type = request.json['attack_type']
    target_mac = request.json['target_mac']
    gateway_mac = request.json.get('gateway_mac')
    interface = request.json.get('interface', 'wlan0')
    
    if attack_type == 'deauth':
        perform_deauth_attack(target_mac, gateway_mac, interface)
    elif attack_type == 'handshake_capture':
        perform_handshake_capture(target_mac, interface)
    elif attack_type == 'evil_twin':
        perform_evil_twin_attack(target_mac, interface)
    elif attack_type == 'wps_bruteforce':
        perform_wps_bruteforce(target_mac, interface)
    elif attack_type == 'mitm':
        perform_mitm_attack(target_mac, gateway_mac, interface)
    elif attack_type == 'arp_spoof_bypass':
        arp_spoof_bypass(interface)
    elif attack_type == 'mac_filter_bypass':
        disable_mac_filtering(interface)
    elif attack_type == 'dns_spoofing':
        perform_dns_spoofing(interface)
    else:
        return jsonify({'status': 'Unknown attack type'})

    return jsonify({'status': f'{attack_type} attack initiated'})

@app.route('/perform_advanced_attack', methods=['POST'])
def advanced_attack():
    attack_type = request.json['attack_type']
    new_mac = request.json.get('new_mac')
    interface = request.json.get('interface', 'wlan0')

    if attack_type == 'karma':
        perform_karma_attack(interface)
    elif attack_type == 'mac_spoof':
        change_mac_address(interface, new_mac)
    elif attack_type == 'dhcp_spoof':
        perform_dhcp_spoofing(interface)
    elif attack_type == 'ssl_stripping':
        perform_ssl_stripping(interface)
    else:
        return jsonify({'status': 'Unknown advanced attack type'})

    return jsonify({'status': f'{attack_type} advanced attack initiated'})

if __name__ == '__main__':
    app.run(debug=True)
