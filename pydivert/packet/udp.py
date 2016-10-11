import struct

from pydivert.packet.header import Header, PayloadMixin, PortMixin
from pydivert.util import PY2


class UDPHeader(Header, PayloadMixin, PortMixin):
    header_len = 8

    @property
    def payload(self):
        return PayloadMixin.payload.fget(self)

    @payload.setter
    def payload(self, val):
        PayloadMixin.payload.fset(self, val)
        self.payload_len = len(val)

    if PY2:
        pass
    else:
        payload.__doc__ = PayloadMixin.payload.__doc__

    @property
    def payload_len(self):
        return struct.unpack_from("!H", self.raw, 4)[0] - 8

    @payload_len.setter
    def payload_len(self, val):
        self.raw[4:6] = struct.pack("!H", val + 8)