import analyze
import sniff

sn = sniff.Sniffer()
an = analyze.Analyzer()

sn.scan(sn.router_ip + '/24')
print(sn.arp_table)

print("Host we monitor:", list(sn.arp_table.keys())[0])
sn.add(list(sn.arp_table.keys())[0])
sn.start(an.feed)
