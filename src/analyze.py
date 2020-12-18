import os
import time
from urllib.parse import unquote

from scapy.layers import inet, dns, http
from scapy.packet import Packet
from scapy.utils import wrpcap

import attack
from target import Target


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
        # print("src: %s, dst: %s" % (p[inet.IP].src, p[inet.IP].dst))

        # IP ban
        if p[inet.IP].src in self.ip_ban or p[inet.IP].dst in self.ip_ban:
            pass

        # DNS: IP and domain ban
        if p.haslayer(dns.DNS):
            if p[dns.DNS].qdcount != 0:
                domain = p[dns.DNS].qd.qname.decode('ascii', 'replace')
                print('[DNS Request]', domain)

        # HTTP: domain and content ban
        if p.haslayer(http.HTTPRequest):
            domain = p[http.HTTPRequest].fields['Host'].decode('ascii', 'replace')
            url = p[http.HTTPRequest].fields['Host'] + p[http.HTTPRequest].fields['Path']
            url = unquote(url.decode('ascii', 'replace'))
            print('[HTTP Request]', url)
            data = p[http.HTTPRequest].payload
            if len(data):
                print('[HTTP Request Post]', data)

        if p.haslayer(http.HTTPResponse):
            pass

        attack.tcp_rst(p, p[inet.IP].src in Target.ip_map)
