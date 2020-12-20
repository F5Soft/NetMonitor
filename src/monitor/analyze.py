import json
from urllib import parse

from scapy.layers import inet, dns, http
from scapy.packet import Packet

from monitor.target import Target


def in_list(content: str, ban: set):
    for b in ban:
        if b in content:
            return True
    return False


class Analyzer:
    def __init__(self):
        """
        Traffic Analyzer Class
        :param log_path: pcap export path
        """
        self.ip_ban = set()
        self.domain_ban = set()
        self.content_ban = set()

        self.count = 0
        self.cnt = {'cnt_arp': 0,
                    'cnt_ip4': {'all': 0,
                                'tcp': {'all': 0, 'tls': 0, 'http': 0, 'dns': 0},
                                'udp': {'all': 0, 'ssdp': 0, 'qicq': 0, 'dns': 0},
                                'snmp': 0,
                                'icmp': 0},
                    'cnt_ip6': {'all': 0,
                                'tcp': {'all': 0, 'tls': 0, 'http': 0, 'dns': 0},
                                'udp': {'all': 0, 'ssdp': 0, 'qicq': 0, 'dns': 0},
                                'snmp': 0,
                                'icmp': 0}}
        self.pkg_info = {'no': 0, 'eth_src': ' ', 'eth_dst': ' ', 'ip_src': ' ',
                         'ip_dst': ' ', 'port_src': ' ', 'port_dst': ' ', 'protol': {'IP': ' ', 'top': ' '}}

    def feed(self, p: Packet):
        """
        Analyze single packet
        :param p: scapy packet
        """

        if p.haslayer('Ether'):
            self.count += 1
            self.pkg_info['eth_src'] = p['Ether'].src
            self.pkg_info['eth_dst'] = p['Ether'].dst
            if p.haslayer('IP'):
                self.pkg_info['ip_src'] = p['IP'].src
                self.pkg_info['ip_dst'] = p['IP'].dst
                self.cnt['cnt_ip4']['all'] += 1
                self.pkg_info['protol']['IP'] = 'IPv4'
                if p.haslayer('TCP'):
                    self.cnt['cnt_ip4']['tcp']['all'] += 1
                    self.pkg_info['protol']['top'] = 'TCP'
                    if p.haslayer('HTTP'):
                        self.cnt['cnt_ip4']['tcp']['http'] += 1
                        self.pkg_info['protol']['top'] = 'HTTP'
                    elif p.haslayer('TLS'):
                        self.cnt['cnt_ip4']['tcp']['tls'] += 1
                        self.pkg_info['protol']['top'] = 'TLS'
                    elif p.haslayer('DNS'):
                        self.cnt['cnt_ip4']['tcp']['dns'] += 1
                        self.pkg_info['protol']['top'] = 'DNS'
                elif p.haslayer('UDP'):
                    self.cnt['cnt_ip4']['udp']['all'] += 1
                    self.pkg_info['protol']['top'] = 'UDP'
                    if p.haslayer('DNS'):
                        self.cnt['cnt_ip4']['udp']['dns'] += 1
                        self.pkg_info['protol']['top'] = 'DNS'
                elif p.haslayer('SNMP'):
                    self.cnt['cnt_ip4']['snmp'] += 1
                    self.pkg_info['protol']['top'] = 'SNMP'
                elif p.haslayer('ICMP'):
                    self.cnt['cnt_ip4']['icmp'] += 1
                    self.pkg_info['protol']['top'] = 'ICMP'
            elif p.haslayer('IPv6'):
                self.pkg_info['ip_src'] = p['IPv6'].src
                self.pkg_info['ip_dst'] = p['IPv6'].dst
                self.cnt['cnt_ip6']['all'] += 1
                self.pkg_info['protol']['IP'] = 'IPv6'
                if p.haslayer('TCP'):
                    self.cnt['cnt_ip6']['tcp']['all'] += 1
                    self.pkg_info['protol']['top'] = 'TCP'
                    if p.haslayer('HTTP'):
                        self.cnt['cnt_ip6']['tcp']['http'] += 1
                        self.pkg_info['protol']['top'] = 'HTTP'
                    elif p.haslayer('TLS'):
                        self.cnt['cnt_ip6']['tcp']['tls'] += 1
                        self.pkg_info['protol']['top'] = 'TLS'
                    elif p.haslayer('DNS'):
                        self.cnt['cnt_ip6']['tcp']['dns'] += 1
                        self.pkg_info['protol']['top'] = 'DNS'
                elif p.haslayer('UDP'):
                    self.cnt['cnt_ip6']['udp']['all'] += 1
                    self.pkg_info['protol']['top'] = 'UDP'
                    if p.haslayer('DNS'):
                        self.cnt['cnt_ip6']['udp']['dns'] += 1
                        self.pkg_info['protol']['top'] = 'DNS'
                elif p.haslayer('SNMP'):
                    self.cnt['cnt_ip6']['snmp'] += 1
                    self.pkg_info['protol']['top'] = 'SNMP'
                elif p.haslayer('ICMPv6'):
                    self.cnt['cnt_ip6']['icmp'] += 1
                    self.pkg_info['protol']['top'] = 'ICMP'
            elif p.haslayer('ARP'):
                self.cnt['cnt_arp'] += 1
                self.pkg_info['protol']['top'] = 'ARP'

        self.pkg_info['no'] = self.count
        try:
            self.pkg_info['port_src'] = p.sport
            self.pkg_info['port_dst'] = p.dport
        except:
            pass

        self.http(p)
        print(self.cnt)
        # print(self.pkg_info)
        # print()

        # attack.dns_poison(p)
        # attack.tcp_rst(p)

    def http(self, p: http.HTTP):
        if p.haslayer(http.HTTPRequest):
            domain = p[http.HTTPRequest].Host.decode('ascii', 'replace')
            url = p[http.HTTPRequest].Host + p[http.HTTPRequest].Path
            url = parse.unquote(url.decode('ascii', 'replace'))
            data = bytes(p[http.HTTPRequest].payload)
            form_data = parse.parse_qs(data)
            try:
                json_data = json.loads(data)
            except json.JSONDecodeError:
                json_data = {}

            Target.add_stats(domain)
            Target.add_history(url)
            if 'username' in form_data:
                Target.add_password(domain, form_data['username'][0], form_data.get('password', ''))
            if 'username' in json_data:
                Target.add_password(domain, json_data['username'], json_data.get('password', ''))
            if domain in self.domain_ban or in_list(data, self.content_ban):
                Target.ban(60)
            print(url, data)


        elif p.haslayer(http.HTTPResponse):
            data = p[http.HTTPResponse].payload

            if in_list(data, self.content_ban):
                Target.ban(60)

    def dns(self, p: dns.DNS):
        pass

    def oicq(self, p: inet.UDP):
        pass

    def ftp(self, p: inet.TCP):
        pass

    def telnet(self, p: inet.TCP):
        pass
