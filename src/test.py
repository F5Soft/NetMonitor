from monitor.analyze import Analyzer
from monitor.sniff import Sniffer

sn = Sniffer(iface='WLAN')  # iface=ifaces.dev_from_name("vEthernet (WSL)"))
an = Analyzer()

# net = input("Please input IPv4 network: ")
# if len(net) != 0:
#     print(sn.scan(net))
# net6 = input("Please input IPv6 network: ")
# if len(net6) != 0:
#     print(sn.scan(net6))

print(sn.scan())
print(sn.scan6())

sn.set(input("target mac:"))
sn.start(an.feed, 10)
