import analyze
import sniff

sn = sniff.Sniffer()
an = analyze.Analyzer()

sn.scan(sn.router_ip + '/24')
print(sn.arp_table)
sn.add('172.20.10.8')
sn.start(an.feed)
