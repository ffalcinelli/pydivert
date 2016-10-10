from pydivert.packet.header import Header, PayloadMixin
from pydivert.util import indexbyte as i


class ICMPHeader(Header, PayloadMixin):
    header_len = 4

    @property
    def type(self):
        return i(self.raw[0])

    @type.setter
    def type(self, val):
        self.raw[0] = i(val)

    @property
    def code(self):
        return i(self.raw[1])

    @code.setter
    def code(self, val):
        self.raw[1] = i(val)


class ICMPv4Header(ICMPHeader):
    pass


class ICMPv6Header(ICMPHeader):
    pass
