from pydivert.packet.header import Header, PayloadMixin
from pydivert.util import indexbyte as i


class ICMPHeader(Header, PayloadMixin):
    header_len = 4

    @property
    def type(self):
        """
        The ICMP message type.
        """
        return i(self.raw[0])

    @type.setter
    def type(self, val):
        self.raw[0] = i(val)

    @property
    def code(self):
        """
        The ICMP message code.
        """
        return i(self.raw[1])

    @code.setter
    def code(self, val):
        self.raw[1] = i(val)


class ICMPv4Header(ICMPHeader):
    pass


class ICMPv6Header(ICMPHeader):
    pass
