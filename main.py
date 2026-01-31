import ipaddress
import os
import platform
import socket
import subprocess
import time

import nmap
import psutil
from yaspin import yaspin


def normalize_mac(raw_mac):
    return raw_mac.upper().replace('-', ':')

def get_ip_by_mac_windows(mac):
    raw = subprocess.check_output(['arp', '-a'], text=True)
    for line in raw.splitlines():
        line = normalize_mac(line)
        if mac in line:
            return line.split()[0]
    return None

def get_ip_by_mac_linux(mac):
    mac = normalize_mac(mac)

    def find_ip_in_output(raw):
        for line in raw.splitlines():
            if mac in normalize_mac(line):
                return line.split()[0]
        return None

    for cmd in (['ip', '-4', 'neigh'], ['arp', '-an'], ['arp', '-n']):
        try:
            raw = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
        ip = find_ip_in_output(raw)
        if ip:
            return ip

    try:
        with open('/proc/net/arp', 'r', encoding='utf-8') as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and mac in normalize_mac(parts[3]):
                    return parts[0]
    except FileNotFoundError:
        pass
    return None

OUI_MODEL_MAP = {
    'B8:27:EB': 'Raspberry Pi 1/2/3',
    'DC:A6:32': 'Raspberry Pi 4/400/CM4/5',
    'E4:5F:01': 'Raspberry Pi 4/400/CM4/5',
    '28:CD:C1': 'Raspberry Pi 4/400/CM4/5',
    '2C:CF:67': 'Raspberry Pi 4/400/CM4/5',
    'D8:3A:DD': 'Raspberry Pi 4/400/CM4/5'
}

def get_default_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def get_active_ipv4_subnet():
    default_ip = get_default_local_ip()

    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family == socket.AF_INET and a.address == default_ip and a.netmask:
                net = ipaddress.IPv4Network((a.address, a.netmask), strict=False)
                return str(net)

def scan_pi_by_oui(subnet):
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-sn')

    pis = []
    for host in nm.all_hosts():
        info = nm[host]
        addresses = info.get('addresses', {})
        mac = addresses.get('mac', '').upper()

        for prefix, model in OUI_MODEL_MAP.items():
            if mac.startswith(prefix):
                pis.append((host, mac, model))
                break
    return pis

def scan_ssh_port(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '22')
    try:
        return nm[ip]['tcp'][22]['state']
    except KeyError:
        return False

def scan_ping_ssh(port, subnet):
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments=f'-p {port} --open')

    pis = []
    
    for host in nm.all_hosts():
        if nm[host].has_tcp(port) and nm[host]['tcp'][port]['state'] == 'open':
            addresses = nm[host].get('addresses', {})
            mac = addresses.get('mac', '').upper()

            for prefix, model in OUI_MODEL_MAP.items():
                if mac.startswith(prefix):
                    pis.append((host, mac, model))
                    break
            pis.append((host, mac, ''))

    return pis



mode = str(input(
    'Enter scan mode.\n' \
    '[1] Get Raspberry Pi IP by specific MAC address (very fast)\n' \
    '[2] Get possible Raspberry Pi IP by comparing OUI (medium)\n' \
    '[3] Get possible Raspberry Pi IP by scanning which specific port is open (medium)\n' \
    'If you know the MAC of your RPI, use [1]. Otherwise, use [2] or [3]: '
))

if mode == '1':
    mac = str(input('Enter the MAC address of your Raspberry Pi (full MAC is not required, accecpt both "-" and ":" for separator, e.g. d8-3a-dd-11-2 or D8:3A:DD:11:2): '))
    sp = yaspin(text=f'[Scanning devices which MAC starts with {mac}]', color='cyan')
    sp.start()

    mac = normalize_mac(mac)
    ip = ''
    if platform.system() == 'Windows': ip = get_ip_by_mac_windows(mac)
    if platform.system() == 'Linux': ip = get_ip_by_mac_linux(mac)
    if not ip:
        sp.stop()
        print('------------------------------------------------------------')
        print(f'❌ Device with MAC {mac} not found.')
        print('------------------------------------------------------------')
    else:
        sp.stop()
        print('------------------------------------------------------------')
        print(f'✅ Found a Raspberry Pi device!')
        print(f'IP: {ip}')
        print(f'MAC: {mac}')
        model = ''
        for o, m in OUI_MODEL_MAP.items():
            if mac.startswith(o): model = m
        print(f'Model: {model}')
        print('22 port (SSH): ', scan_ssh_port(ip))
        print('------------------------------------------------------------')

elif mode == '2':
    subnet = get_active_ipv4_subnet()
    sp = yaspin(text=f'[Scanning devices which match Raspberry Pi OUI on subnet {subnet}]', color='cyan')
    sp.start()
    pis = scan_pi_by_oui(subnet)
    sp.stop()
    if pis:
        print('------------------------------------------------------------')
        print(f'✅ Found Raspberry Pi device(s)!')

        for (ip, mac, model) in pis:
            print(f'IP: {ip}')
            print(f'MAC: {mac}')
            print(f'Model: {model}')
            print('22 port (SSH): ', scan_ssh_port(ip))
            print('------------------------------------------------------------')
    else:
        print('------------------------------------------------------------')
        print(f'❌ Possible Raspberry Pi devices not found.')
        print('------------------------------------------------------------')

elif mode == '3':
    port = input('Enter the port you want to scan (default 22): ')

    if port == '' or port.isdigit():
        if port == '': port = 22
        else: port = int(port)
        subnet = get_active_ipv4_subnet()
        sp = yaspin(text=f'[Scanning devices which port {port} is open on subnet {subnet}]', color='cyan')
        sp.start()
        pis = scan_ping_ssh(port, subnet)
        sp.stop()

        if pis:
            print(f'✅ Found device(s) which 22 port (SSH) is open!')
            print('------------------------------------------------------------')
            for (ip, mac, model) in pis:
                print(f'IP: {ip}')
                print(f'MAC: {mac}')
                print(f'Model: {model}')
                print('------------------------------------------------------------')
        else:
            print('------------------------------------------------------------')
            print(f'❌ Possible Raspberry Pi devices not found.')
            print('------------------------------------------------------------')
    else:
        print('------------------------------------------------------------')
        print(f'❌ Consider check your input. You entered `{port}`, but the script only accepts `1 ~ 65535`')
        print('------------------------------------------------------------')

else:
    print('------------------------------------------------------------')
    print(f'❌ Consider check your input. You entered `{mode}`, but the script only accepts `1, 2, 3`')
    print('------------------------------------------------------------')

os.system('pause')
