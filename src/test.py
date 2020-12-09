import analyze
import sniff

sn = sniff.Sniffer()
an = analyze.Analyzer()
sn.scan('192.168.1.0/24')
print(sn.targets)
sn.start(an.feed)
