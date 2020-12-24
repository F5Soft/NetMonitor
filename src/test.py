import time

from monitor.analyze import Analyzer
from monitor.sniff import Sniffer

sn = Sniffer(iface='WLAN')  # iface=ifaces.dev_from_name("vEthernet (WSL)"))
an = Analyzer()

sn.scan(1)
sn.scan6(1)
sn.scan(1)

sn.set("dc:a6:32:af:98:ec")
print(sn.target_ip)
sn.start(an.feed, 5)

while 1:
    time.sleep(10)
