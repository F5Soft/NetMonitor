import json
import re
import time
from collections import defaultdict
from urllib import parse

from scapy.layers import inet, dns, http, inet6
from scapy.packet import Packet, Raw

from monitor import attack


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
        self.dns_map = dict()
        self.dns_map6 = dict()

        self.count = 0
        self.cnt = {'cnt_arp': 0,
                    'cnt_ip4': {'all': 0,
                                'tcp': {'all': 0, 'tls': 0, 'http': 0, 'dns': 0, 'ftp': 0},
                                'udp': {'all': 0, 'oicq': 0, 'dns': 0},
                                'snmp': 0,
                                'icmp': 0},
                    'cnt_ip6': {'all': 0,
                                'tcp': {'all': 0, 'tls': 0, 'http': 0, 'dns': 0, 'ftp': 0},
                                'udp': {'all': 0, 'oicq': 0, 'dns': 0},
                                'snmp': 0,
                                'icmp': 0}}
        self.info = []

        self.web_history = list()
        self.web_stats = defaultdict(int)
        self.password = dict()

        self._ftp_username = None
        self._telnet_buf = None

    def feed(self, p: Packet):
        """
        Analyze single packet
        :param p: scapy packet
        """

        # 统计

        pkg_info = {'no': 0, 'eth_src': ' ', 'eth_dst': ' ', 'ip_src': ' ',
                    'ip_dst': ' ', 'port_src': ' ', 'port_dst': ' ', 'protol': {'IP': ' ', 'top': ' '}}

        self.count += 1
        pkg_info['eth_src'] = p['Ether'].src
        pkg_info['eth_dst'] = p['Ether'].dst
        if p.haslayer('IP'):
            pkg_info['ip_src'] = p['IP'].src
            pkg_info['ip_dst'] = p['IP'].dst
            self.cnt['cnt_ip4']['all'] += 1
            pkg_info['protol']['IP'] = 'IPv4'
            if p.haslayer('TCP'):
                self.cnt['cnt_ip4']['tcp']['all'] += 1
                pkg_info['protol']['top'] = 'TCP'
                if p.haslayer('HTTP'):
                    self.cnt['cnt_ip4']['tcp']['http'] += 1
                    pkg_info['protol']['top'] = 'HTTP'
                    self.http(p)
                elif p.haslayer('TLS'):
                    self.cnt['cnt_ip4']['tcp']['tls'] += 1
                    pkg_info['protol']['top'] = 'TLS'
                elif p.haslayer('DNS'):
                    self.cnt['cnt_ip4']['tcp']['dns'] += 1
                    pkg_info['protol']['top'] = 'DNS'
                    self.dns(p)
                elif p.sport in [20, 21] or p.dport in [20, 21]:
                    self.cnt['cnt_ip4']['tcp']['ftp'] += 1
                    pkg_info['protol']['top'] = 'FTP'
                    self.ftp(p)
            elif p.haslayer('UDP'):
                self.cnt['cnt_ip4']['udp']['all'] += 1
                pkg_info['protol']['top'] = 'UDP'
                if p.haslayer('DNS'):
                    self.cnt['cnt_ip4']['udp']['dns'] += 1
                    pkg_info['protol']['top'] = 'DNS'
                    self.dns(p)
                elif p.sport == 8000 or p.dport == 8000:
                    self.cnt['cnt_ip4']['udp']['oicq'] += 1
                    pkg_info['protol']['top'] = 'OICQ'
                    self.oicq(p)
            elif p.haslayer('SNMP'):
                self.cnt['cnt_ip4']['snmp'] += 1
                pkg_info['protol']['top'] = 'SNMP'
            elif p.haslayer('ICMP'):
                self.cnt['cnt_ip4']['icmp'] += 1
                pkg_info['protol']['top'] = 'ICMP'
        elif p.haslayer('IPv6'):
            pkg_info['ip_src'] = p['IPv6'].src
            pkg_info['ip_dst'] = p['IPv6'].dst
            self.cnt['cnt_ip6']['all'] += 1
            pkg_info['protol']['IP'] = 'IPv6'
            if p.haslayer('TCP'):
                self.cnt['cnt_ip6']['tcp']['all'] += 1
                pkg_info['protol']['top'] = 'TCP'
                if p.haslayer('HTTP'):
                    self.cnt['cnt_ip6']['tcp']['http'] += 1
                    pkg_info['protol']['top'] = 'HTTP'
                    self.http(p)
                elif p.haslayer('TLS'):
                    self.cnt['cnt_ip6']['tcp']['tls'] += 1
                    pkg_info['protol']['top'] = 'TLS'
                elif p.haslayer('DNS'):
                    self.cnt['cnt_ip6']['tcp']['dns'] += 1
                    pkg_info['protol']['top'] = 'DNS'
                    self.dns(p)
                elif p.sport == 20 or p.dport == 21:
                    self.cnt['cnt_ip6']['tcp']['ftp'] += 1
                    pkg_info['protol']['top'] = 'FTP'
                    self.ftp(p)
            elif p.haslayer('UDP'):
                self.cnt['cnt_ip6']['udp']['all'] += 1
                pkg_info['protol']['top'] = 'UDP'
                if p.haslayer('DNS'):
                    self.cnt['cnt_ip6']['udp']['dns'] += 1
                    pkg_info['protol']['top'] = 'DNS'
                    self.dns(p)
                elif p.sport == 8000 or p.dport == 8000:
                    self.cnt['cnt_ip6']['udp']['oicq'] += 1
                    pkg_info['protol']['top'] = 'OICQ'
                    self.oicq(p)
            elif p.haslayer('SNMP'):
                self.cnt['cnt_ip6']['snmp'] += 1
                pkg_info['protol']['top'] = 'SNMP'
            elif p.haslayer('ICMPv6'):
                self.cnt['cnt_ip6']['icmp'] += 1
                pkg_info['protol']['top'] = 'ICMP'
        elif p.haslayer('ARP'):
            self.cnt['cnt_arp'] += 1
            pkg_info['protol']['top'] = 'ARP'

        pkg_info['no'] = self.count
        try:
            pkg_info['port_src'] = p.sport
            pkg_info['port_dst'] = p.dport
        except:
            pass

        if len(self.info) < 10:
            self.info.append(pkg_info)
        else:
            self.info.pop(0)
            self.info.append(pkg_info)

        # print(self.cnt)

        # print(pkg_info)
        # print()

        # attack.dns_poison(p)
        # attack.tcp_rst(p)

    def http(self, p: Packet):
        if p.haslayer(http.HTTPRequest):
            domain = p[http.HTTPRequest].Host.decode('ascii', 'replace')
            url = p[http.HTTPRequest].Host + p[http.HTTPRequest].Path
            url = parse.unquote(url.decode('ascii', 'replace'))
            data = bytes(p[http.HTTPRequest].payload)
            try:
                form_data = parse.parse_qs(data)
            except Exception:
                form_data = {}
            try:
                json_data = json.loads(data)
            except Exception:
                json_data = {}
            self.add_stats(domain)
            self.add_history(url)
            if b'username' in form_data:
                username = form_data[b'username'][0].decode('ascii', 'replace')
                password = form_data.get(b'password', b'')[0].decode('ascii', 'replace')
                self.add_password('http://' + domain, username, password)
            if 'username' in json_data:
                username = json_data['username']
                password = json_data.get('password', '')
                self.add_password('http://' + domain, username, password)
            if domain in self.domain_ban or in_list(data, self.content_ban):
                attack.ban = True
            print('[HTTP]', url)

        elif p.haslayer(http.HTTPResponse):
            data = p[http.HTTPResponse].payload
            if in_list(data, self.content_ban):
                attack.ban = True

    def dns(self, p: Packet):
        if p.haslayer(dns.DNSQR):
            domain = p[dns.DNSQR].qname.decode('ascii', 'replace').strip('.')
            if domain in self.domain_ban:
                attack.ban = True

            if p.haslayer(dns.DNSRR) and p[dns.DNSRR].type in [1, 28]:
                ip = p[dns.DNSRR].rdata
                if p[dns.DNSRR].type == 1:
                    self.dns_map[ip] = domain
                else:
                    self.dns_map6[ip] = domain
                if ip in self.ip_ban:
                    attack.ban = True
            else:
                print('[DNS]', domain)

    def oicq(self, p: Packet):
        raw = bytes(p[inet.UDP].payload)
        qq = str(int.from_bytes(raw[7:11], 'big', signed=False))
        print('[OICQ]', qq)
        self.add_password('QQ', qq, '')

    def ftp(self, p: Raw):
        raw = bytes(p[inet.TCP].payload).decode('ascii', 'replace')
        username = re.findall('(?i)USER (.*)', raw)
        password = re.findall('(?i)PASS (.*)', raw)
        if username:
            username = username[0].replace('\\r\\n', '')
            self._ftp_username = username
            print('[FTP] USER', username)
        if password and self._ftp_username is not None:
            password = password[0].replace('\\r\\n', '')
            print('[FTP] PASS', password)
            if p.haslayer(inet.IP):
                self.add_password('ftp://' + p[inet.IP].dst, self._ftp_username, password)
            else:
                self.add_password('ftp://' + p[inet6.IPv6].dst, self._ftp_username, password)
            self._ftp_username = None

    def telnet(self, p: Raw):
        pass

    def add_stats(self, domain: str):
        self.web_stats[domain] += 1

    def add_history(self, url: str):
        self.web_history.append((time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), url))

    def add_password(self, where: str, username: str, password: str):
        self.password[where] = (username, password)
