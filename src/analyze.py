import os
import time

from scapy.layers import inet, dns, http
from scapy.packet import Packet
from scapy.utils import wrpcap


class Analyzer:
    def __init__(self, log_path='../log'):
        self.ip_ban = set()
        self.domain_ban = set()
        self.data_ban = set()
        self.log = os.path.join(log_path, time.strftime("%Y-%m-%d.pcap", time.localtime()))

    def feed(self, p: Packet):
        wrpcap(self.log, p, append=True)
        # IP ban
        if p[inet.IP].src in self.ip_ban or p[inet.IP].dst in self.ip_ban:
            pass
        # DNS: IP and domain ban
        if p.haslayer(dns.DNS):
            pass
        # HTTP: domain and content ban
        if p.haslayer(http.HTTPRequest):
            print(p[http.HTTPRequest].fields['Host'] + p[http.HTTPRequest].fields['Path'])
            if len(p[http.HTTPRequest].payload):
                print(p[http.HTTPRequest].payload)
        if p.haslayer(http.HTTPResponse):
            pass
