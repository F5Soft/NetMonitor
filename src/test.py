from scapy.arch import ifaces

import analyze
import sniff

sn = sniff.Sniffer(iff=ifaces.dev_from_name("vEthernet (WSL)"))
an = analyze.Analyzer()

if input("Do you want to perform a network scan? (y/n)") == 'y':
    net = input("Please input IPv4 network: ")
    if len(net) != 0:
        sn.scan(net)
    net6 = input("Please input IPv6 network: ")
    if len(net6) != 0:
        sn.scan(net6)

sn.add('172.30.111.239')

print("Monitored targets:")
for target in sn.targets:
    print(target)
sn.start(an.feed, spoof=False)
