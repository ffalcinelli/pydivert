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

    if PY2 or PY34:
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

    if PY2 or PY34:
        pass
    else:
        packet_len.__doc__ = IPHeader.packet_len.__doc__