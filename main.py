import platform
import subprocess
import os
import nmap


def get_ip_by_mac_windows(mac):
    raw = subprocess.check_output(['arp', '-a'], text=True)
    for line in raw.splitlines():
        if mac.lower() in line.lower():
            return line.split()[0]
    return None

def get_ip_by_mac_linux(mac):
    print('[TODO! Not implemented yet QWQ]')
    return None

OUI_MODEL_MAP = {
    'B8:27:EB': 'Raspberry Pi 1/2/3',
    'DC:A6:32': 'Raspberry Pi 4/400/CM4/5',
    'E4:5F:01': 'Raspberry Pi 4/400/CM4/5',
    '28:CD:C1': 'Raspberry Pi 4/400/CM4/5',
    '2C:CF:67': 'Raspberry Pi 4/400/CM4/5',
    'D8:3A:DD': 'Raspberry Pi 4/400/CM4/5'
}

def scan_pi_by_oui(subnet='192.168.1.0/24'):
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

def scan_ping_ssh(port, subnet='192.168.1.0/24'):
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
print('[Scanning...]')

if mode == '1':
    mac = str(input('Enter the MAC address of your Raspberry Pi (full MAC is not required, e.g.: D8-3A-DD-11-2): '))
    mac = mac.replace('-', ':')
    ip = ''
    if platform.system() == 'Windows': ip = get_ip_by_mac_windows(mac)
    if platform.system() == 'Linux': ip = get_ip_by_mac_linux(mac)
    if not ip:
        print('------------------------------------------------------------')
        print(f'❌ Device with MAC {mac} not found.')
        print('------------------------------------------------------------')
    else:
        print('------------------------------------------------------------')
        print(f'✅ Found a Raspberry Pi device!')
        print(f'IP: {ip}')
        print(f'MAC: {mac}')
        model = ''
        for (o, m) in enumerate(OUI_MODEL_MAP):
            if mac.startswith(o): model = m
        print(f'Model: {model}')
        print('22 port (SSH): ', scan_ssh_port(ip))
        print('------------------------------------------------------------')

elif mode == '2':
    pis = scan_pi_by_oui()
    if pis:
        print(f'✅ Found Raspberry Pi device(s)!')
        print('------------------------------------------------------------')

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
        pis = scan_ping_ssh(port)
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

print('Done!')
os.system("pause")