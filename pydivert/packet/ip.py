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
from pydivert.util import PY2, PY34, flag_property, indexbyte as i, raw_property


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

    # @property
    # def packet_len(self):
    #     return struct.unpack_from("!H", self.raw, 2)[0]
    #
    # @packet_len.setter
    # def packet_len(self, val):
    #     self.raw[2:4] = struct.pack("!H", val)

    @property
    def hdr_len(self):
        return i(self.raw[0]) & 0x0F

    @hdr_len.setter
    def hdr_len(self, val):
        if i(val) < 5:
            raise ValueError("IP header length must be greater or equal than 5")
        self.raw[0] = 0x40 | i(val)

    tos = raw_property('!B', 1)
    packet_len = raw_property('!H', 2)
    ident = raw_property('!H', 4)

    evil_bit = flag_property('evil_bit', 6, 0b10000000)
    df = flag_property('df', 6, 0b01000000)
    mf = flag_property('mf', 6, 0b00100000)

    ttl = raw_property('!B', 8, docs='Time to live')
    protocol = raw_property('!B', 9)
    cksum = raw_property('!H', 10)


    @property
    def flags(self):
        return i(self.raw[6]) >> 5

    @flags.setter
    def flags(self, val):
        self.raw[6] = (val << 5) | (self.frag_offset & 0xFF00)

    @property
    def frag_offset(self):
        return struct.unpack_from("!H", self.raw, 6)[0] & 0x1FFF

    @frag_offset.setter
    def frag_offset(self, val):
        self.raw[6:8] = struct.pack("!H", (self.flags << 13) | (val & 0x1FFF))

    @property
    def dscp(self):
        return (i(self.raw[1]) >> 2) & 0x3F

    @dscp.setter
    def dscp(self, val):
        self.raw[1] = (i(val) << 2) | (self.ecn & 0x03)

    @property
    def ecn(self):
        return i(self.raw[1]) & 0x03

    @ecn.setter
    def ecn(self, val):
        self.raw[1] = (self.dscp << 2) | (i(val) & 0x3F)

    if not PY2 and not PY34:
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
