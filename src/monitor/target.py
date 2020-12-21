import threading
import time
from collections import defaultdict

from scapy.layers import l2


class Target:
    host_ip = []
    host_ip6 = []
    host_mac = ''

    banned = False
    web_history = list()
    web_stats = defaultdict(int)
    password = dict()

    @staticmethod
    def set(ip: str, ip6: str = None) -> bool:
        mac = l2.getmacbyip(ip)
        if mac is not None:
            Target.ip = ip
            Target.ip6 = ip6
            Target.mac = mac
            return True
        return False

    @staticmethod
    def add_stats(domain: str):
        Target.web_stats[domain] += 1

    @staticmethod
    def add_history(url: str):
        Target.web_history.append((time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), url))

    @staticmethod
    def add_password(where: str, username: str, password: str):
        Target.password[where] = (username, password)

    @staticmethod
    def ban(timeout: int):
        threading.Thread(target=Target._ban, args=(timeout,)).start()

    @staticmethod
    def clear():
        Target.web_history.clear()
        Target.web_stats.clear()
        Target.password.clear()

    @staticmethod
    def _ban(timeout: int):
        Target.banned = True
        time.sleep(timeout)
        Target.banned = False
