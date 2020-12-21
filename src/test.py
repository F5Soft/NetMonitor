from scapy.arch import ifaces

from monitor.analyze import Analyzer
from monitor.sniff import Sniffer
from monitor.target import Target

sn = Sniffer(iff=ifaces.dev_from_name("vEthernet (WSL)"))
an = Analyzer()

# net = input("Please input IPv4 network: ")
# if len(net) != 0:
#     print(sn.scan(net))
# net6 = input("Please input IPv6 network: ")
# if len(net6) != 0:
#     print(sn.scan(net6))

Target.set('172.30.98.6')
print(Target.mac)
sn.start(an.feed, spoof=False)
