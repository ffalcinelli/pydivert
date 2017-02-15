# -*- coding: utf-8 -*-
# Copyright (C) 2016  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import socket
import struct

from pydivert.packet.header import Header
from pydivert.util import PY2, PY34


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

    @property
    def hdr_len(self):
        return self.raw[0] & 0x0F

    @hdr_len.setter
    def hdr_len(self, val):
        if val < 5:
            raise ValueError("IP header length must be greater or equal than 5")
        self.raw[0] = 0x40 | val

    @property
    def ident(self):
        return struct.unpack_from("!H", self.raw, 4)[0]

    @ident.setter
    def ident(self, val):
        struct.pack_into("!H", self.raw, 4, val)

    @property
    def flags(self):
        # return struct.unpack_from("!B", self.raw, 6)[0] & 0x07
        return self.raw[6] >> 5

    @flags.setter
    def flags(self, val):
        # self.raw[6:8] = struct.pack("!H", (val & 0x07) | (self.frag_offset << 3))
        # struct.pack_into("!B", self.raw, 6, (val << 5) | (self.frag_offset & 0xFF00))
        self.raw[6] = (val << 5) | (self.frag_offset & 0xFF00)

    @property
    def frag_offset(self):
        return struct.unpack_from("!H", self.raw, 6)[0] & 0x1FFF

    @frag_offset.setter
    def frag_offset(self, val):
        self.raw[6:8] = struct.pack("!H", (self.flags << 13) | (val & 0x1FFF))

    # TODO: make this a smarter property
    def _get_flag(self, index, offset):
        # return (struct.unpack_from("!B", self.raw, index)[0] & (1 << offset)) != 0
        return (self.raw[index] & (1 << offset)) != 0

    def _set_flag(self, index, offset, val):
        if val:
            self.raw[index] |= 1 << offset
        else:
            self.raw[index] &= ~(1 << offset)

    @property
    def evil_bit(self):
        return self._get_flag(6, 7)

    @evil_bit.setter
    def evil_bit(self, val):
        self._set_flag(6, 7, val)

    @property
    def df(self):
        return self._get_flag(6, 6)

    @df.setter
    def df(self, val):
        self._set_flag(6, 6, val)

    @property
    def mf(self):
        return self._get_flag(6, 5)

    @mf.setter
    def mf(self, val):
        self._set_flag(6, 5, val)

    @property
    def tos(self):
        return self.raw[1]

    @tos.setter
    def tos(self, val):
        self.raw[1] = val

    @property
    def dscp(self):
        return (self.raw[1] >> 2) & 0x3F

    @dscp.setter
    def dscp(self, val):
        self.raw[1] = (val << 2) | (self.ecn & 0x03)

    @property
    def ecn(self):
        return self.raw[1] & 0x03

    @ecn.setter
    def ecn(self, val):
        self.raw[1] = (self.dscp << 2) | (val & 0x3F)

    @property
    def ttl(self):
        return self.raw[8]

    @ttl.setter
    def ttl(self, val):
        self.raw[8] = val

    @property
    def protocol(self):
        return self.raw[9]

    @protocol.setter
    def protocol(self, val):
        self.raw[9] = val

    @property
    def cksum(self):
        return struct.unpack_from("!H", self.raw, 10)[0]

    @cksum.setter
    def cksum(self, val):
        struct.pack_into("!H", self.raw, 10, val)

    # TODO: support options field
    # @property
    # def options(self):
    #     if self.ihl > 5:
    #         return self.raw[20, self.ihl*4]
    #
    # @options.setter
    # def options(self, val):
    #   pass

    if not PY2 and not PY34:  # applied De Morgan here :-)
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

    if not PY2 and not PY34:
        packet_len.__doc__ = IPHeader.packet_len.__doc__
