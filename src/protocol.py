from scapy.data import UDP_SERVICES
from scapy.fields import ShortEnumField, ShortField, XShortField, ByteField, SignedIntField, SignedShortField, \
    XByteField
from scapy.packet import Packet


class OICQ(Packet):
    name = "OICQ"
    fields_desc = [XByteField("flag", None),
                   XShortField("version", None),
                   XShortField("command", None),
                   SignedShortField("sequence", None),
                   SignedIntField("number", None)]