import socket
import struct

from pydivert.packet.header import Header
from pydivert.util import PY2


class IPHeader(Header):
    _src_addr = slice(0, 0)
    _dst_addr = slice(0, 0)
    _af = None

    @property
    def src_addr(self):
        """
        The packet source address
        """
        try:
            return socket.inet_ntop(self._af, self.raw[self._src_addr].tobytes())
        except (ValueError, socket.error):
            pass

    @src_addr.setter
    def src_addr(self, val):
        self.raw[self._src_addr] = socket.inet_pton(self._af, val)

    @property
    def dst_addr(self):
        """
        The packet destination address
        """
        try:
            return socket.inet_ntop(self._af, self.raw[self._dst_addr].tobytes())
        except (ValueError, socket.error):
            pass

    @dst_addr.setter
    def dst_addr(self, val):
        self.raw[self._dst_addr] = socket.inet_pton(self._af, val)

    @property
    def packet_len(self):
        """
        The total packet length, including *all* headers, as reported by the IP header.
        """
        raise NotImplementedError()  # pragma: no cover

    @packet_len.setter
    def packet_len(self, val):
        raise NotImplementedError()  # pragma: no cover


class IPv4Header(IPHeader):
    _src_addr = slice(12, 16)
    _dst_addr = slice(16, 20)
    _af = socket.AF_INET

    @property
    def packet_len(self):
        return struct.unpack_from("!H", self.raw, 2)[0]

    @packet_len.setter
    def packet_len(self, val):
        self.raw[2:4] = struct.pack("!H", val)

    if PY2:
        pass
    else:
        packet_len.__doc__ = IPHeader.packet_len.__doc__


class IPv6Header(IPHeader):
    _src_addr = slice(8, 24)
    _dst_addr = slice(24, 40)
    _af = socket.AF_INET6

    @property
    def packet_len(self):
        return struct.unpack_from("!H", self.raw, 4)[0] + 40

    @packet_len.setter
    def packet_len(self, val):
        self.raw[4:6] = struct.pack("!H", val - 40)

    if PY2:
        pass
    else:
        packet_len.__doc__ = IPHeader.packet_len.__doc__