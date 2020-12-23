import time

from monitor.analyze import Analyzer
from monitor.sniff import Sniffer

sn = Sniffer(iface='WLAN')  # iface=ifaces.dev_from_name("vEthernet (WSL)"))
an = Analyzer()

sn.scan(1)
sn.scan6(1)
sn.scan(1)

sn.set("d6:84:85:c1:57:76")
print(sn.target_ip)
sn.start(an.feed, 5)
an.ban_method = [False, True, False, False, True]
an.ban()

while 1:
    time.sleep(10)
