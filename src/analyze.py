import os
import time

from scapy.layers import inet, dns, http
from scapy.packet import Packet
from scapy.utils import wrpcap


class Analyzer:
    def __init__(self, log_path='../log'):
        """
        Traffic Analyzer Class
        :param log_path: pcap export path
        """
        self.ip_ban = set()
        self.domain_ban = set()
        self.data_ban = set()
        self.log = os.path.join(log_path, time.strftime("%Y-%m-%d.pcap", time.localtime()))

    def feed(self, p: Packet):
        """
        Analyze single packet
        :param p: scapy packet
        """
        wrpcap(self.log, p, append=True)
        print("src: %s, dst: %s" % (p[inet.IP].src, p[inet.IP].dst))
        # IP ban
        if p[inet.IP].src in self.ip_ban or p[inet.IP].dst in self.ip_ban:
            pass
        # DNS: IP and domain ban
        if p.haslayer(dns.DNS):
            pass
        # HTTP: domain and content ban
        if p.haslayer(http.HTTPRequest):
            print(p[http.HTTPRequest].fields['Host'] + p[http.HTTPRequest].fields['Path'])
            data = p[http.HTTPRequest].payload
            if len(data):
                print("FORM POST: ", data)
        if p.haslayer(http.HTTPResponse):
            pass
