from scapy.layers import inet, dns, http
from scapy.packet import Packet

import attack


class Analyzer:
    def __init__(self):
        """
        Traffic Analyzer Class
        :param log_path: pcap export path
        """
        self.protocol_stats = dict()
        self.web_history = list()
        self.web_stats = dict()
        self.password = list()

    def feed(self, p: Packet):
        """
        Analyze single packet
        :param p: scapy packet
        """

        attack.dns_poison(p)
        attack.tcp_rst(p)

    def http(self, p: http.HTTP):
        if p.haslayer(http.HTTPRequest):
            pass
        pass

    def dns(self, p: dns.DNS):
        pass

    def oicq(self, p: inet.UDP):
        pass

    def ftp(self, p: inet.TCP):
        pass

    def telnet(self, p: inet.TCP):
        pass
