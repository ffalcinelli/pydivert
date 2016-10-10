from pydivert.packet.header import Header, PayloadMixin, PortMixin
from pydivert.util import indexbyte as i, PY2


def flagproperty(name, bit):
    @property
    def flag(self):
        return bool(i(self.raw[13]) & bit)

    @flag.setter
    def flag(self, val):
        flags = i(self.raw[13])
        if val:
            flags |= bit
        else:
            flags &= ~bit

        self.raw[13] = i(flags)

    if PY2:
        pass  # .__doc__ is readonly on Python 2.
    else:
        flag.__doc__ = """
            The TCP {} flag, if the packet is valid TCP.
            None, otherwise.
            """.format(name.upper())

    return flag


class TCPHeader(Header, PayloadMixin, PortMixin):
    urg = flagproperty("syn", 0b100000)
    ack = flagproperty("ack", 0b010000)
    psh = flagproperty("psh", 0b001000)
    rst = flagproperty("rst", 0b000100)
    syn = flagproperty("syn", 0b000010)
    fin = flagproperty("fin", 0b000001)

    @property
    def header_len(self):
        return (i(self.raw[12]) >> 4) * 4
