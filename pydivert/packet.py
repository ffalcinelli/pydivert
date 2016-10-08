# -*- coding: utf-8 -*-
# Copyright (C) 2016  Fabio Falcinelli
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

from pydivert.consts import Direction, IPV6_EXT_HEADERS, Protocol
from pydivert.util import cached_property, indexbytes


class Packet(object):
    def __init__(self, raw, interface, direction):
        self.raw = raw
        self.interface = interface
        self.direction = direction

    def __repr__(self):
        direction = Direction(self.direction).name.lower()
        protocol = self.protocol[0]
        try:
            protocol = Protocol(protocol).name.lower()
        except ValueError:
            pass
        return '<Packet \n' \
               '    direction="{}"\n' \
               '    interface="{}" subinterface="{}"\n' \
               '    src="{}"\n' \
               '    dst="{}"\n' \
               '    protocol="{}">\n' \
               '{}\n' \
               '</Packet>'.format(
            direction,
            self.interface[0],
            self.interface[1],
            "{}:{}".format(self.src_addr, self.src_port),
            "{}:{}".format(self.dst_addr, self.dst_port),
            protocol,
            self.payload
        )

    @property
    def is_outbound(self):
        return self.direction == Direction.OUTBOUND

    @property
    def is_inbound(self):
        return self.direction == Direction.INBOUND

    @property
    def is_loopback(self):
        return self.interface[0] == 1

    @cached_property
    def address_family(self):
        if len(self.raw) >= 20:
            v = indexbytes(self.raw, 0) >> 4
            if v == 4:
                return socket.AF_INET
            if v == 6:
                return socket.AF_INET6

    @cached_property
    def protocol(self):
        """
        Returns a (ipproto, proto_start) tuple.
        ipproto is the IP protocol in use, e.g. Protocol.TCP or Protocol.UDP.
        proto_start denotes the beginning of the protocol data.
        """
        if self.address_family == socket.AF_INET:
            proto = indexbytes(self.raw, 9)
            start = (indexbytes(self.raw, 0) & 0b1111) * 4
        elif self.address_family == socket.AF_INET6:
            proto = indexbytes(self.raw, 6)

            # skip over well-known ipv6 headers
            start = 40
            while proto in IPV6_EXT_HEADERS:
                if start >= len(self.raw):
                    # less than two bytes left
                    start = None
                    proto = None
                    break
                if proto == Protocol.FRAGMENT:
                    hdrlen = 8
                elif proto == Protocol.AH:
                    hdrlen = (indexbytes(self.raw, start + 1) + 2) * 4
                else:
                    # Protocol.HOPOPT, Protocol.DSTOPTS, Protocol.ROUTING
                    hdrlen = (indexbytes(self.raw, start + 1) + 1) * 8
                proto = indexbytes(self.raw, start)
                start += hdrlen
        else:
            start = None
            proto = None

        out_of_bounds = (
            (proto == Protocol.TCP and start + 12 >= len(self.raw)) or
            (proto == Protocol.UDP and start + 8 > len(self.raw))
        )
        if out_of_bounds:
            # special-case tcp/udp so that we can rely on .protocol for the port properties.
            start = None
            proto = None

        return proto, start

    @property
    def src_addr(self):
        try:
            if self.address_family == socket.AF_INET:
                return socket.inet_ntop(socket.AF_INET, self.raw[12:16])
            if self.address_family == socket.AF_INET6:
                return socket.inet_ntop(socket.AF_INET6, self.raw[8:24])
        except (ValueError, socket.error):
            # ValueError may be raised by inet_ntop, socket.error by win_inet_pton.
            pass

    @property
    def dst_addr(self):
        try:
            if self.address_family == socket.AF_INET:
                return socket.inet_ntop(socket.AF_INET, self.raw[16:20])
            if self.address_family == socket.AF_INET6:
                return socket.inet_ntop(socket.AF_INET6, self.raw[24:40])
        except (ValueError, socket.error):
            # ValueError may be raised by inet_ntop, socket.error by win_inet_pton.
            pass

    @src_addr.setter
    def src_addr(self, val):
        if self.address_family == socket.AF_INET:
            self.raw = self.raw[:12] + socket.inet_pton(socket.AF_INET, val) + self.raw[16:]
        elif self.address_family == socket.AF_INET6:
            self.raw = self.raw[:8] + socket.inet_pton(socket.AF_INET6, val) + self.raw[24:]
        else:
            raise ValueError("Unknown address family")

    @dst_addr.setter
    def dst_addr(self, val):
        if self.address_family == socket.AF_INET:
            self.raw = self.raw[:16] + socket.inet_pton(socket.AF_INET, val) + self.raw[20:]
        elif self.address_family == socket.AF_INET6:
            self.raw = self.raw[:24] + socket.inet_pton(socket.AF_INET6, val) + self.raw[40:]
        else:
            raise ValueError("Unknown address family")

    @property
    def src_port(self):
        ipproto, proto_start = self.protocol
        if ipproto in {Protocol.TCP, Protocol.UDP}:
            return struct.unpack_from("!H", self.raw, proto_start)[0]

    @property
    def dst_port(self):
        ipproto, proto_start = self.protocol
        if ipproto in {Protocol.TCP, Protocol.UDP}:
            return struct.unpack_from("!H", self.raw, proto_start + 2)[0]

    @src_port.setter
    def src_port(self, val):
        ipproto, proto_start = self.protocol
        if ipproto in {Protocol.TCP, Protocol.UDP}:
            self.raw = self.raw[:proto_start] + struct.pack("!H", val) + self.raw[proto_start + 2:]
        else:
            raise ValueError("Unknown protocol")

    @dst_port.setter
    def dst_port(self, val):
        ipproto, proto_start = self.protocol
        if ipproto in {Protocol.TCP, Protocol.UDP}:
            self.raw = self.raw[:proto_start + 2] + struct.pack("!H", val) + self.raw[proto_start + 4:]
        else:
            raise ValueError("Unknown protocol")

    @property
    def payload(self):
        ipproto, proto_start = self.protocol
        if ipproto == Protocol.TCP:
            header_len = (indexbytes(self.raw, proto_start + 12) >> 4) * 4
            return self.raw[proto_start + header_len:]
        elif ipproto == Protocol.UDP:
            return self.raw[proto_start + 8:]

    @payload.setter
    def payload(self, val):
        raise NotImplementedError()
