import analyze
import sniff

sn = sniff.Sniffer()  # iff=ifaces.dev_from_name("vEthernet (WSL)"))
an = analyze.Analyzer()

net = input("Please input IPv4 network: ")
if len(net) != 0:
    print(sn.scan(net))
net6 = input("Please input IPv6 network: ")
if len(net6) != 0:
    print(sn.scan(net6))

sn.add('192.168.43.211')
sn.start(an.feed)
