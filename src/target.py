class Target:
    ip_map = dict()
    ip6_map = dict()

    def __init__(self, ip: str, mac: str, version=4):
        self.version = version
        self.mac = mac

        if self.version == 4:
            self.ip = ip
            self.ip6 = None
            Target.ip_map[ip] = self
        elif self.version == 6:
            self.ip = None
            self.ip6 = ip
            Target.ip6_map[ip] = self

        self.banned = False

    def __str__(self):
        return (self.ip if self.version == 4 else self.ip6) + ' at ' + str(self.mac)

    def __repr__(self):
        return (self.ip if self.version == 4 else self.ip6) + ' at ' + str(self.mac)

    @staticmethod
    def clear():
        Target.ip_map.clear()
        Target.ip6_map.clear()
