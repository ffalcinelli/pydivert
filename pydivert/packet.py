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
import ctypes
import socket
import struct
import sys

from pydivert import windivert_dll
from pydivert.consts import Direction, IPV6_EXT_HEADERS, Protocol
from pydivert.util import cached_property, indexbytes


def tcp_flag(name, bit):
    @property
    def flag(self):
        ipproto, proto_start = self.protocol
        if ipproto == Protocol.TCP:
            return bool(indexbytes(self.raw, proto_start + 13) & bit)

    @flag.setter
    def flag(self, val):
        ipproto, proto_start = self.protocol
        if ipproto == Protocol.TCP:
            flags = indexbytes(self.raw, proto_start + 13)
            if val:
                flags |= bit
            else:
                flags &= ~bit
            flags = struct.pack("!B", flags)

            self.raw = self.raw[:proto_start + 13] + flags + self.raw[proto_start + 14:]
        else:
            raise ValueError("Protocol is not TCP")

    if sys.version_info < (3, 0):
        pass  # .__doc__ is readonly on Python 2.
    else:
        flag.__doc__ = """
            Returns:
                The TCP {} flag, if the packet is valid TCP.
                None, otherwise.
            """.format(name.upper())

    return flag


class Packet(object):
    """
    A single packet, possibly including an IP header, a TCP/UDP header and a payload.
    Creation of packets is cheap, parsing is done on first attribute access.

    While the raw packet can be modified directly, the protocol and address types will be cached.
    """

    def __init__(self, raw, interface, direction):
        self.raw = raw
        self.interface = interface
        self.direction = direction

    def __repr__(self):
        direction = Direction(self.direction).name.lower()
        protocol = self.protocol[0]
        if self.is_icmp46:
            extra = '\n    type="{}" code="{}"'.format(self.icmp_type, self.icmp_code)
        elif self.is_tcp:
            flags = " ".join(
                x.upper()
                    for x in ("fin", "syn", "rst", "psh", "ack", "urg")
                    if getattr(self, "tcp_" + x)
            )
            extra = '\n    {}'.format(flags)
        else:
            extra = ''
        if self.ip_packet_len is not None:
            bytes_cut_off = self.ip_packet_len - len(self.raw)
            if bytes_cut_off != 0:
                extra += '\n    bytes-cut-off="{}"'.format(bytes_cut_off)
        try:
            protocol = Protocol(protocol).name.lower()
        except ValueError:
            pass
        return '<Packet \n' \
               '    direction="{}"\n' \
               '    interface="{}" subinterface="{}"\n' \
               '    src="{}"\n' \
               '    dst="{}"\n' \
               '    protocol="{}"{}>\n' \
               '{}\n' \
               '</Packet>'.format(
            direction,
            self.interface[0],
            self.interface[1],
            ":".join(str(x) for x in (self.src_addr, self.src_port) if x is not None),
            ":".join(str(x) for x in (self.dst_addr, self.dst_port) if x is not None),
            protocol,
            extra,
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
        """
        True, if the packet is on the loopback interface.
        False, otherwise.
        """
        return self.interface[0] == 1

    @cached_property
    def address_family(self):
        """
        Returns:
            The packet address family:
                socket.AF_INET, if IPv4
                socket.AF_INET6, if IPv6
                None, otherwise.
        """
        if len(self.raw) >= 20:
            v = indexbytes(self.raw, 0) >> 4
            if v == 4:
                return socket.AF_INET
            if v == 6:
                return socket.AF_INET6

    @cached_property
    def is_ipv4(self):
        """
        True, if the packet has a IPv4 header.
        False, otherwise.
        """
        return self.address_family == socket.AF_INET

    @cached_property
    def is_ipv6(self):
        """
        True, if the packet has a IPv6 header.
        False, otherwise.
        """
        return self.address_family == socket.AF_INET6

    @cached_property
    def protocol(self):
        """
        Returns:
            A (ipproto, proto_start) tuple.
            ipproto is the IP protocol in use, e.g. Protocol.TCP or Protocol.UDP.
            proto_start denotes the beginning of the protocol data.
            If the packet does not match our expectations, both ipproto and proto_start are None.
        """
        if self.is_ipv4:
            proto = indexbytes(self.raw, 9)
            start = (indexbytes(self.raw, 0) & 0b1111) * 4
        elif self.is_ipv6:
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
            (proto == Protocol.TCP and start + 20 > len(self.raw)) or
            (proto == Protocol.UDP and start + 8 > len(self.raw)) or
            (proto in {Protocol.ICMP, Protocol.ICMPV6} and start + 4 > len(self.raw))
        )
        if out_of_bounds:
            # special-case tcp/udp so that we can rely on .protocol for the port properties.
            start = None
            proto = None

        return proto, start

    @cached_property
    def is_tcp(self):
        """
        True, if the packet is TCP.
        False, otherwise.
        """
        return self.protocol[0] == Protocol.TCP

    @cached_property
    def is_udp(self):
        """
        True, if the packet is UDP.
        False, otherwise.
        """
        return self.protocol[0] == Protocol.UDP

    @cached_property
    def is_icmp46(self):
        """
        True, if the packet is ICMP or ICMPv6.
        False, otherwise.
        """
        return self.protocol[0] in {Protocol.ICMP, Protocol.ICMPV6}

    @property
    def src_addr(self):
        """
        Returns:
            The source address, if the packet is valid IP or IPv6.
            None, otherwise.
        """
        try:
            if self.is_ipv4:
                return socket.inet_ntop(socket.AF_INET, self.raw[12:16])
            if self.is_ipv6:
                return socket.inet_ntop(socket.AF_INET6, self.raw[8:24])
        except (ValueError, socket.error):
            # ValueError may be raised by inet_ntop, socket.error by win_inet_pton.
            pass

    @property
    def dst_addr(self):
        """
        Returns:
            The destination address, if the packet is valid IP or IPv6.
            None, otherwise.
        """
        try:
            if self.is_ipv4:
                return socket.inet_ntop(socket.AF_INET, self.raw[16:20])
            if self.is_ipv6:
                return socket.inet_ntop(socket.AF_INET6, self.raw[24:40])
        except (ValueError, socket.error):
            # ValueError may be raised by inet_ntop, socket.error by win_inet_pton.
            pass

    @src_addr.setter
    def src_addr(self, val):
        if self.is_ipv4:
            self.raw = self.raw[:12] + socket.inet_pton(socket.AF_INET, val) + self.raw[16:]
        elif self.is_ipv6:
            self.raw = self.raw[:8] + socket.inet_pton(socket.AF_INET6, val) + self.raw[24:]
        else:
            raise ValueError("Unknown address family")

    @dst_addr.setter
    def dst_addr(self, val):
        if self.is_ipv4:
            self.raw = self.raw[:16] + socket.inet_pton(socket.AF_INET, val) + self.raw[20:]
        elif self.is_ipv6:
            self.raw = self.raw[:24] + socket.inet_pton(socket.AF_INET6, val) + self.raw[40:]
        else:
            raise ValueError("Unknown address family")

    @property
    def src_port(self):
        """
        Returns:
            The source port, if the packet is valid TCP or UDP.
            None, otherwise.
        """
        ipproto, proto_start = self.protocol
        if ipproto in {Protocol.TCP, Protocol.UDP}:
            return struct.unpack_from("!H", self.raw, proto_start)[0]

    @property
    def dst_port(self):
        """
        Returns:
            The destination port, if the packet is valid TCP or UDP.
            None, otherwise.
        """
        ipproto, proto_start = self.protocol
        if ipproto in {Protocol.TCP, Protocol.UDP}:
            return struct.unpack_from("!H", self.raw, proto_start + 2)[0]

    @src_port.setter
    def src_port(self, val):
        ipproto, proto_start = self.protocol
        if ipproto in {Protocol.TCP, Protocol.UDP}:
            self.raw = self.raw[:proto_start] + struct.pack("!H", val) + self.raw[proto_start + 2:]
        else:
            raise ValueError("Protocol is neither TCP nor UDP")

    @dst_port.setter
    def dst_port(self, val):
        ipproto, proto_start = self.protocol
        if ipproto in {Protocol.TCP, Protocol.UDP}:
            self.raw = self.raw[:proto_start + 2] + struct.pack("!H", val) + self.raw[proto_start + 4:]
        else:
            raise ValueError("Protocol is neither TCP nor UDP")

    @property
    def ip_packet_len(self):
        """
        The total packet length (including all headers, including ipv6), as reported by the IP header.
        This is useful to determine if the packet has been cut off, e.g. by receiving it into a too small buffer.
        """
        if self.is_ipv4:
            return struct.unpack_from("!H", self.raw, 2)[0]
        elif self.is_ipv6:
            return struct.unpack_from("!H", self.raw, 4)[0] + 40

    @ip_packet_len.setter
    def ip_packet_len(self, val):
        if self.is_ipv4:
            self.raw = self.raw[:2] + struct.pack("!H", val) + self.raw[4:]
        elif self.is_ipv6:
            self.raw = self.raw[:4] + struct.pack("!H", val - 40) + self.raw[6:]
        else:  # pragma: no cover
            raise RuntimeError("Unknown address family")  # should never be called

    @cached_property
    def _payload_start(self):
        ipproto, proto_start = self.protocol
        if ipproto == Protocol.TCP:
            tcp_header_len = (indexbytes(self.raw, proto_start + 12) >> 4) * 4
            return proto_start + tcp_header_len
        elif ipproto == Protocol.UDP:
            return proto_start + 8
        elif ipproto in {Protocol.ICMP, Protocol.ICMPV6}:
            return proto_start + 4

    @property
    def payload(self):
        """
        Returns:
            The payload, if the packet is valid TCP, UDP, ICMP or ICMPv6.
            None, otherwise.
        """
        if self._payload_start:
            return self.raw[self._payload_start:]

    @payload.setter
    def payload(self, val):
        ipproto, proto_start = self.protocol
        if ipproto in {Protocol.TCP, Protocol.ICMP, Protocol.ICMPV6}:
            self.raw = self.raw[:self._payload_start] + val
        elif ipproto == Protocol.UDP:
            self.raw = (
                self.raw[:proto_start + 4]  # ip header + ports
                + struct.pack("!H", len(val) + 8)  # udp length field
                + b"\x00\x00"  # checksum
                + val  # content
            )
        else:
            raise ValueError("Protocol is neither TCP, UDP, ICMP nor ICMPv6")

        self.ip_packet_len = len(val) + self._payload_start

    def recalculate_checksums(self, flags=0):
        """
        (Re)calculates the checksum for any IPv4/ICMP/ICMPv6/TCP/UDP checksum present in the given packet.
        Individual checksum calculations may be disabled via the appropriate flag.
        Typically this function should be invoked on a modified packet before it is injected with WinDivert.send().
        Returns the number of checksums calculated.

        See: https://reqrypt.org/windivert-doc.html#divert_helper_calc_checksums
        """
        buff = ctypes.create_string_buffer(self.raw)
        num = windivert_dll.WinDivertHelperCalcChecksums(ctypes.byref(buff), len(self.raw), flags)
        self.raw = buff.raw[:len(self.raw)]  # slice to cut off the null byte added by create_string_buffer
        return num

    @property
    def icmp_type(self):
        """
        Returns:
            The ICMP type, if the packet is valid ICMP or ICMPv6.
            None, otherwise.
        """
        ipproto, proto_start = self.protocol
        if ipproto in {Protocol.ICMP, Protocol.ICMPV6}:
            return indexbytes(self.raw, proto_start)

    @property
    def icmp_code(self):
        """
        Returns:
            The ICMP type, if the packet is valid ICMP or ICMPv6.
            None, otherwise.
        """
        ipproto, proto_start = self.protocol
        if ipproto in {Protocol.ICMP, Protocol.ICMPV6}:
            return indexbytes(self.raw, proto_start + 1)

    @icmp_type.setter
    def icmp_type(self, val):
        ipproto, proto_start = self.protocol
        if ipproto in {Protocol.ICMP, Protocol.ICMPV6}:
            self.raw = self.raw[:proto_start + 0] + struct.pack("!B", val) + self.raw[proto_start + 1:]
        else:
            raise ValueError("Protocol is neither ICMP nor ICMPv6")

    @icmp_code.setter
    def icmp_code(self, val):
        ipproto, proto_start = self.protocol
        if ipproto in {Protocol.ICMP, Protocol.ICMPV6}:
            self.raw = self.raw[:proto_start + 1] + struct.pack("!B", val) + self.raw[proto_start + 2:]
        else:
            raise ValueError("Protocol is neither ICMP nor ICMPv6")

    tcp_urg = tcp_flag("syn", 0b100000)
    tcp_ack = tcp_flag("ack", 0b010000)
    tcp_psh = tcp_flag("psh", 0b001000)
    tcp_rst = tcp_flag("rst", 0b000100)
    tcp_syn = tcp_flag("syn", 0b000010)
    tcp_fin = tcp_flag("fin", 0b000001)
