from scapy.packet import Packet

import attack


class Analyzer:
    def __init__(self):
        """
        Traffic Analyzer Class
        :param log_path: pcap export path
        """

    def feed(self, p: Packet):
        """
        Analyze single packet
        :param p: scapy packet
        """

        attack.dns_poison(p)
        attack.tcp_rst(p)
