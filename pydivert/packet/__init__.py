# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of either:
#
# 1) The GNU Lesser General Public License as published by the Free
#    Software Foundation, either version 3 of the License, or (at your
#    option) any later version.
#
# 2) The GNU General Public License as published by the Free Software
#    Foundation, either version 2 of the License, or (at your option)
#    any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License and the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# and the GNU General Public License along with this program.  If not,
# see <https://www.gnu.org/licenses/>.

from __future__ import annotations

import ctypes
import socket
import sys
from functools import cached_property
from typing import Any

from pydivert import windivert_dll
from pydivert.consts import IPV6_EXT_HEADERS, Direction, Layer, Protocol
from pydivert.packet.header import Header, PayloadMixin, PortMixin
from pydivert.packet.icmp import ICMPHeader, ICMPv4Header, ICMPv6Header
from pydivert.packet.ip import IPHeader, IPv4Header, IPv6Header
from pydivert.packet.tcp import TCPHeader
from pydivert.packet.udp import UDPHeader
from pydivert.windivert_dll import WinDivertAddress


class Packet:
    """
    A single packet, possibly including an IP header, a TCP/UDP header and a payload.
    Creation of packets is cheap, parsing is done on first attribute access.
    """

    __slots__ = (
        "raw",
        "interface",
        "direction",
        "timestamp",
        "_loopback",
        "_impostor",
        "_sniffed",
        "ip_checksum",
        "tcp_checksum",
        "udp_checksum",
        "layer",
        "event",
        "flow",
        "socket",
        "reflect",
        "_bsd_addr",
        "_cached_buff_len",
        "_cached_buff_id",
        "_cached_buff",
        "__dict__",  # Needed for cached_property
    )

    __match_args__ = (
        "ipv4",
        "ipv6",
        "tcp",
        "udp",
        "icmpv4",
        "icmpv6",
        "payload",
        "direction",
        "src_addr",
        "dst_addr",
        "src_port",
        "dst_port",
    )

    __repr_fields__: tuple[str, ...] = (
        "direction",
        "dst_addr",
        "dst_port",
        "event",
        "flow",
        "icmpv4",
        "icmpv6",
        "interface",
        "ip_checksum",
        "ipv4",
        "ipv6",
        "is_impostor",
        "is_inbound",
        "is_loopback",
        "is_outbound",
        "is_sniffed",
        "layer",
        "payload",
        "raw",
        "reflect",
        "socket",
        "src_addr",
        "src_port",
        "tcp",
        "tcp_checksum",
        "timestamp",
        "udp",
        "udp_checksum",
    )

    def __init__(
        self,
        raw: bytes | bytearray | memoryview,
        interface: tuple[int, int] | None = None,
        direction: Direction = Direction.OUTBOUND,
        timestamp: int = 0,
        loopback: bool = False,
        impostor: bool = False,
        sniffed: bool = False,
        ip_checksum: bool = False,
        tcp_checksum: bool = False,
        udp_checksum: bool = False,
        layer: Layer = Layer.NETWORK,
        event: int = 0,
        flow: Any | None = None,
        socket: Any | None = None,
        reflect: Any | None = None,
    ) -> None:
        if isinstance(raw, (bytes, bytearray)):
            raw = memoryview(bytearray(raw))
        self.raw: memoryview = raw
        """The raw packet bytes as a `memoryview`."""
        self.interface: tuple[int, int] = interface or (0, 0)
        """The interface index and sub-interface index where the packet was captured."""
        self.direction: Direction = direction
        """The packet direction (inbound or outbound)."""
        self.timestamp: int = timestamp
        """The capture timestamp (QueryPerformanceCounter value)."""
        self._loopback: bool = loopback
        self._impostor: bool = impostor
        self._sniffed: bool = sniffed
        self.ip_checksum: bool = ip_checksum
        """Indicates if the IP checksum was verified by hardware offloading."""
        self.tcp_checksum: bool = tcp_checksum
        """Indicates if the TCP checksum was verified by hardware offloading."""
        self.udp_checksum: bool = udp_checksum
        """Indicates if the UDP checksum was verified by hardware offloading."""
        self.layer: Layer = layer
        """The WinDivert layer that captured this packet."""
        self.event: int = event
        """The WinDivert event type."""
        self.flow: Any | None = flow
        """The flow metadata (for Layer.FLOW)."""
        self.socket: Any | None = socket
        """The socket metadata (for Layer.SOCKET)."""
        self.reflect: Any | None = reflect
        """The reflect metadata (for Layer.FLOW)."""
        self._bsd_addr: Any | None = None
        """Internal storage for BSD/macOS divert socket address."""
        self._cached_buff_len: int | None = None

        self._cached_buff_id: int | None = None
        self._cached_buff: Any | None = None

    def __repr__(self) -> str:
        fields = []
        for k in self.__repr_fields__:
            try:
                v = getattr(self, k)
                if v is None:
                    continue
                if k == "payload":
                    if v and len(v) > 20:
                        v = v[:20] + b"..."
                elif isinstance(v, Header):
                    # For nested headers, just show their class name or a summary
                    v = f"{v.__class__.__name__}(...)"
                elif isinstance(v, memoryview):
                    v = f"<memoryview of {len(v)} bytes>"
                fields.append(f"{k}={v!r}")
            except (AttributeError, ValueError):
                continue
        return f"Packet({', '.join(fields)})"

    @property
    def is_outbound(self) -> bool:
        """
        Indicates if the packet is outbound.
        Convenience method for ``.direction``.
        """
        return self.direction == Direction.OUTBOUND

    @property
    def is_inbound(self) -> bool:
        """
        Indicates if the packet is inbound.
        Convenience method for ``.direction``.
        """
        return self.direction == Direction.INBOUND

    @property
    def is_loopback(self) -> bool:
        """
        Indicates if the packet is a loopback packet.
        """
        return self._loopback

    @is_loopback.setter
    def is_loopback(self, val: bool) -> None:
        self._loopback = bool(val)

    @property
    def is_impostor(self) -> bool:
        """
        Indicates if the packet is an impostor packet.
        """
        return self._impostor

    @is_impostor.setter
    def is_impostor(self, val: bool) -> None:
        self._impostor = bool(val)

    @property
    def is_sniffed(self) -> bool:
        """
        Indicates if the packet is a sniffed packet.
        """
        return self._sniffed

    @is_sniffed.setter
    def is_sniffed(self, val: bool) -> None:
        self._sniffed = bool(val)

    @cached_property
    def address_family(self) -> int | None:
        """
        The packet address family:
            - socket.AF_INET, if IPv4
            - socket.AF_INET6, if IPv6
            - None, otherwise.
        """
        if len(self.raw) >= 20:
            v = self.raw[0] >> 4
            if v == 4:
                return socket.AF_INET
            if v == 6:
                return socket.AF_INET6
        return None

    def _parse_ipv4_protocol(self) -> tuple[int, int]:
        proto = self.raw[9]
        start = (self.raw[0] & 0b1111) * 4
        return proto, start

    def _parse_ipv6_protocol(self) -> tuple[int | None, int | None]:
        proto = self.raw[6]

        # skip over well-known ipv6 headers
        start = 40
        while proto in IPV6_EXT_HEADERS:
            if start >= len(self.raw):
                # less than two bytes left
                return None, None
            if proto == Protocol.FRAGMENT:
                hdrlen = 8
            elif proto == Protocol.AH:
                hdrlen = (self.raw[start + 1] + 2) * 4  # type: ignore[operator]
            else:
                # Protocol.HOPOPT, Protocol.DSTOPTS, Protocol.ROUTING
                hdrlen = (self.raw[start + 1] + 1) * 8  # type: ignore[operator]
            proto = self.raw[start]
            start += hdrlen  # type: ignore[operator]
        return proto, start

    @cached_property
    def protocol(self) -> tuple[int | None, int | None]:
        """
        - | A (ipproto, proto_start) tuple.
          | ``ipproto`` is the IP protocol in use, e.g. Protocol.TCP or Protocol.UDP.
          | ``proto_start`` denotes the beginning of the protocol data.
          | If the packet does not match our expectations, both ipproto and proto_start are None.
        """
        proto: int | None
        start: int | None

        if self.address_family == socket.AF_INET:
            proto, start = self._parse_ipv4_protocol()
        elif self.address_family == socket.AF_INET6:
            proto, start = self._parse_ipv6_protocol()
        else:
            start = None
            proto = None

        out_of_bounds = (
            (proto == Protocol.TCP and start is not None and start + 20 > len(self.raw))
            or (proto == Protocol.UDP and start is not None and start + 8 > len(self.raw))
            or (proto in {Protocol.ICMP, Protocol.ICMPV6} and start is not None and start + 4 > len(self.raw))
        )
        if out_of_bounds:
            # special-case tcp/udp so that we can rely on .protocol for the port properties.
            start = None
            proto = None

        return proto, start

    @cached_property
    def ipv4(self) -> IPv4Header | None:
        """
        - An IPv4Header instance, if the packet is valid IPv4.
        - None, otherwise.
        """
        if self.address_family == socket.AF_INET:
            return IPv4Header(self)
        return None

    @cached_property
    def ipv6(self) -> IPv6Header | None:
        """
        - An IPv6Header instance, if the packet is valid IPv6.
        - None, otherwise.
        """
        if self.address_family == socket.AF_INET6:
            return IPv6Header(self)
        return None

    @cached_property
    def ip(self) -> IPHeader | None:
        """
        - An IPHeader instance, if the packet is valid IPv4 or IPv6.
        - None, otherwise.
        """
        return self.ipv4 or self.ipv6

    @cached_property
    def icmpv4(self) -> ICMPv4Header | None:
        """
        - An ICMPv4Header instance, if the packet is valid ICMPv4.
        - None, otherwise.
        """
        ipproto, proto_start = self.protocol
        if ipproto == Protocol.ICMP and proto_start is not None:
            return ICMPv4Header(self, proto_start)
        return None

    @cached_property
    def icmpv6(self) -> ICMPv6Header | None:
        """
        - An ICMPv6Header instance, if the packet is valid ICMPv6.
        - None, otherwise.
        """
        ipproto, proto_start = self.protocol
        if ipproto == Protocol.ICMPV6 and proto_start is not None:
            return ICMPv6Header(self, proto_start)
        return None

    @cached_property
    def icmp(self) -> ICMPHeader | None:
        """
        - An ICMPHeader instance, if the packet is valid ICMPv4 or ICMPv6.
        - None, otherwise.
        """
        return self.icmpv4 or self.icmpv6

    @cached_property
    def tcp(self) -> TCPHeader | None:
        """
        - An TCPHeader instance, if the packet is valid TCP.
        - None, otherwise.
        """
        ipproto, proto_start = self.protocol
        if ipproto == Protocol.TCP and proto_start is not None:
            return TCPHeader(self, proto_start)
        return None

    @cached_property
    def udp(self) -> UDPHeader | None:
        """
        - An TCPHeader instance, if the packet is valid UDP.
        - None, otherwise.
        """
        ipproto, proto_start = self.protocol
        if ipproto == Protocol.UDP and proto_start is not None:
            return UDPHeader(self, proto_start)
        return None

    @cached_property
    def _port(self) -> PortMixin | None:
        """header that implements PortMixin"""
        return self.tcp or self.udp

    @cached_property
    def _payload(self) -> PayloadMixin | None:
        """header that implements PayloadMixin"""
        return self.tcp or self.udp or self.icmpv4 or self.icmpv6

    @property
    def src_addr(self) -> str | None:
        """
        - The source address, if the packet is valid IPv4 or IPv6.
        - None, otherwise.
        """
        if self.ip:
            return self.ip.src_addr
        return None

    @src_addr.setter
    def src_addr(self, val: str) -> None:
        if self.ip:
            self.ip.src_addr = val

    @property
    def dst_addr(self) -> str | None:
        """
        - The destination address, if the packet is valid IPv4 or IPv6.
        - None, otherwise.
        """
        if self.ip:
            return self.ip.dst_addr
        return None

    @dst_addr.setter
    def dst_addr(self, val: str) -> None:
        if self.ip:
            self.ip.dst_addr = val

    @property
    def src_port(self) -> int | None:
        """
        - The source port, if the packet is valid TCP or UDP.
        - None, otherwise.
        """
        if self._port:
            return self._port.src_port
        return None

    @src_port.setter
    def src_port(self, val: int) -> None:
        if self._port:
            self._port.src_port = val

    @property
    def dst_port(self) -> int | None:
        """
        - The destination port, if the packet is valid TCP or UDP.
        - None, otherwise.
        """
        if self._port:
            return self._port.dst_port
        return None

    @dst_port.setter
    def dst_port(self, val: int) -> None:
        if self._port:
            self._port.dst_port = val

    @property
    def payload(self) -> bytes | None:
        """
        - The payload, if the packet is valid TCP, UDP, ICMP or ICMPv6.
        - None, otherwise.
        """
        if self._payload:
            return self._payload.payload
        return None

    @payload.setter
    def payload(self, val: bytes | bytearray | memoryview) -> None:
        if self._payload:
            self._payload.payload = val

    def recalculate_checksums(self, flags: int = 0) -> int:
        """
        (Re)calculates the checksum for any IPv4/ICMP/ICMPv6/TCP/UDP checksum present in the given packet.
        Individual checksum calculations may be disabled via the appropriate flag.
        Typically this function should be invoked on a modified packet before it is injected with WinDivert.send().
        Returns the number of checksums calculated.

        See: https://reqrypt.org/windivert-doc.html#divert_helper_calc_checksums
        """
        import sys
        if sys.platform != 'win32':
            from pydivert.util import fallback_recalculate_checksums
            return fallback_recalculate_checksums(self, flags)

        buff, buff_ = self.__to_buffers()
        addr = self.wd_addr
        num: int = windivert_dll.WinDivertHelperCalcChecksums(
            ctypes.byref(buff_), len(self.raw), ctypes.byref(addr), flags
        )
        return num

    @property
    def is_checksum_valid(self) -> bool:
        """
        Check if all checksums in the packet (IP, TCP, UDP, ICMP) are valid.
        This recalculates the checksums on a copy of the packet and compares the results.
        """
        # Create a copy of the packet
        other = Packet(self.raw.tobytes(), layer=self.layer)
        # We must zero out checksums before recalculating, because WinDivertHelperCalcChecksums
        # only fills them if they are 0.
        if other.ipv4:
            other.ipv4.cksum = 0
        if other.tcp:
            other.tcp.cksum = 0  # type: ignore[attr-defined]
        if other.udp:
            other.udp.cksum = 0  # type: ignore[attr-defined]
        if other.icmp:
            other.icmp.cksum = 0  # type: ignore[attr-defined]

        # Set address hints for the helper
        other.wd_addr.IPChecksum = 1 if other.ipv4 else 0
        other.wd_addr.TCPChecksum = 1 if other.tcp else 0
        other.wd_addr.UDPChecksum = 1 if other.udp else 0

        # Recalculate checksums on the copy
        other.recalculate_checksums()
        # Compare raw bytes. If any checksum changed, it means the original was invalid.
        return self.raw.tobytes() == other.raw.tobytes()

    def __to_buffers(self) -> tuple[Any, Any]:
        buff = self.raw.obj
        raw_len = len(self.raw)

        if self._cached_buff is not None and self._cached_buff_len == raw_len and self._cached_buff_id == id(buff):
            return buff, self._cached_buff

        self._cached_buff_len = raw_len
        self._cached_buff_id = id(buff)
        self._cached_buff = (ctypes.c_char * raw_len).from_buffer(buff)
        return buff, self._cached_buff

    @property
    def wd_addr(self) -> WinDivertAddress:
        """
        Gets the address and metadata as a `WINDIVERT_ADDRESS` structure.
        :return: The `WINDIVERT_ADDRESS` structure.
        """
        address = WinDivertAddress()
        address.Timestamp = self.timestamp
        address.Layer = self.layer
        address.Event = self.event
        address.Outbound = 1 if self.direction == Direction.OUTBOUND else 0
        address.Loopback = 1 if self.is_loopback else 0
        address.Impostor = 1 if self.is_impostor else 0
        address.Sniffed = 1 if self.is_sniffed else 0
        address.IPChecksum = 1 if self.ip_checksum else 0
        address.TCPChecksum = 1 if self.tcp_checksum else 0
        address.UDPChecksum = 1 if self.udp_checksum else 0

        if self.layer in (Layer.NETWORK, Layer.NETWORK_FORWARD):
            address.Network.IfIdx, address.Network.SubIfIdx = self.interface
        elif self.layer == Layer.FLOW and self.flow:
            ctypes.pointer(address.Flow)[0] = self.flow
        elif self.layer == Layer.SOCKET and self.socket:
            ctypes.pointer(address.Socket)[0] = self.socket
        elif self.layer == Layer.REFLECT and self.reflect:
            ctypes.pointer(address.Reflect)[0] = self.reflect

        return address

    def matches(self, filter: str, layer: Layer = Layer.NETWORK) -> bool:
        """
        Evaluates the packet against the given packet filter string.
        """
        if sys.platform == "win32":
            return self._matches_win32(filter, layer)
        return self._matches_fallback(filter)

    def _matches_win32(self, filter: str, layer: Layer) -> bool:
        _, buff_ = self.__to_buffers()
        addr = self.wd_addr
        addr.Layer = layer
        return bool(
            windivert_dll.WinDivertHelperEvalFilter(
                filter.encode(),
                ctypes.byref(buff_),
                len(self.raw),
                ctypes.byref(addr),
            )
        )

    def _matches_fallback(self, filter: str) -> bool:
        from pydivert.util import fallback_matches

        return fallback_matches(self, filter)
