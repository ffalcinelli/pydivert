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
        "_interface",
        "_direction",
        "_timestamp",
        "_loopback",
        "_impostor",
        "_sniffed",
        "_ip_checksum",
        "_tcp_checksum",
        "_udp_checksum",
        "_layer",
        "_event",
        "_flow",
        "_socket",
        "_reflect",
        "_bsd_addr",
        "_cached_buff_len",
        "_cached_buff_id",
        "_cached_buff",
        "_wd_addr",
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
        wd_addr: WinDivertAddress | None = None,
    ) -> None:
        if isinstance(raw, memoryview):
            if raw.readonly:
                raw = bytearray(raw)
        elif not isinstance(raw, bytearray):
            raw = bytearray(raw)

        self.raw: memoryview = memoryview(raw)
        """The raw packet bytes as a `memoryview`."""
        self._nfq_pkt: Any | None = None
        """Optional reference to the underlying NetFilterQueue packet."""
        self._bsd_addr: Any | None = None
        """Internal storage for BSD/macOS divert socket address."""
        self._cached_buff_len: int | None = None

        self._cached_buff_id: int | None = None
        self._cached_buff: Any | None = None
        if wd_addr is not None:  # pragma: no cover
            self._wd_addr = wd_addr
            self._interface = (wd_addr.Network.IfIdx, wd_addr.Network.SubIfIdx)
            self._direction = Direction.OUTBOUND if wd_addr.Outbound else Direction.INBOUND
            self._timestamp = wd_addr.Timestamp
            self._loopback = bool(wd_addr.Loopback)
            self._impostor = bool(wd_addr.Impostor)
            self._sniffed = bool(wd_addr.Sniffed)
            self._ip_checksum = bool(wd_addr.IPChecksum)
            self._tcp_checksum = bool(wd_addr.TCPChecksum)
            self._udp_checksum = bool(wd_addr.UDPChecksum)
            self._layer = wd_addr.Layer
            self._event = wd_addr.Event
            self._flow = wd_addr.Flow if self._layer == Layer.FLOW else None
            self._socket = wd_addr.Socket if self._layer == Layer.SOCKET else None
            self._reflect = wd_addr.Reflect if self._layer == Layer.REFLECT else None
        else:
            self._interface = interface or (0, 0)
            self._direction = direction
            self._timestamp = timestamp
            self._loopback = loopback
            self._impostor = impostor
            self._sniffed = sniffed
            self._ip_checksum = ip_checksum
            self._tcp_checksum = tcp_checksum
            self._udp_checksum = udp_checksum
            self._layer = layer
            self._event = event
            self._flow = flow
            self._socket = socket
            self._reflect = reflect
            self._wd_addr = WinDivertAddress()
            self._populate_wd_addr()

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
    def interface(self) -> tuple[int, int]:
        """The interface index and sub-interface index where the packet was captured."""
        return self._interface

    @interface.setter
    def interface(self, val: tuple[int, int]) -> None:
        self._interface = val
        if self._layer in (Layer.NETWORK, Layer.NETWORK_FORWARD):
            self._wd_addr.Network.IfIdx, self._wd_addr.Network.SubIfIdx = val

    @property
    def direction(self) -> Direction:
        """The packet direction (inbound or outbound)."""
        return self._direction

    @direction.setter
    def direction(self, val: Direction) -> None:
        self._direction = val
        self._wd_addr.Outbound = 1 if val == Direction.OUTBOUND else 0

    @property
    def timestamp(self) -> int:
        """The capture timestamp (QueryPerformanceCounter value)."""
        return self._timestamp

    @timestamp.setter
    def timestamp(self, val: int) -> None:
        self._timestamp = val
        self._wd_addr.Timestamp = val

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
        self._wd_addr.Loopback = 1 if val else 0

    @property
    def is_impostor(self) -> bool:
        """
        Indicates if the packet is an impostor packet.
        """
        return self._impostor

    @is_impostor.setter
    def is_impostor(self, val: bool) -> None:
        self._impostor = bool(val)
        self._wd_addr.Impostor = 1 if val else 0

    @property
    def is_sniffed(self) -> bool:
        """
        Indicates if the packet is a sniffed packet.
        """
        return self._sniffed

    @is_sniffed.setter
    def is_sniffed(self, val: bool) -> None:
        self._sniffed = bool(val)
        self._wd_addr.Sniffed = 1 if val else 0

    @property
    def ip_checksum(self) -> bool:
        """Indicates if the IP checksum was verified by hardware offloading."""
        return self._ip_checksum

    @ip_checksum.setter
    def ip_checksum(self, val: bool) -> None:
        self._ip_checksum = bool(val)
        self._wd_addr.IPChecksum = 1 if val else 0

    @property
    def tcp_checksum(self) -> bool:
        """Indicates if the TCP checksum was verified by hardware offloading."""
        return self._tcp_checksum

    @tcp_checksum.setter
    def tcp_checksum(self, val: bool) -> None:
        self._tcp_checksum = bool(val)
        self._wd_addr.TCPChecksum = 1 if val else 0

    @property
    def udp_checksum(self) -> bool:
        """Indicates if the UDP checksum was verified by hardware offloading."""
        return self._udp_checksum

    @udp_checksum.setter
    def udp_checksum(self, val: bool) -> None:
        self._udp_checksum = bool(val)
        self._wd_addr.UDPChecksum = 1 if val else 0

    @property
    def layer(self) -> Layer:
        """The WinDivert layer that captured this packet."""
        return self._layer

    @layer.setter
    def layer(self, val: Layer) -> None:
        self._layer = val
        self._populate_wd_addr()

    @property
    def event(self) -> int:
        """The WinDivert event type."""
        return self._event

    @event.setter
    def event(self, val: int) -> None:
        self._event = int(val)
        self._wd_addr.Event = int(val)

    @property
    def flow(self) -> Any | None:
        """The WinDivert flow metadata (for `Layer.FLOW`)."""
        return self._flow  # pragma: no cover

    @flow.setter
    def flow(self, val: Any | None) -> None:
        self._flow = val
        if self._layer == Layer.FLOW and val is not None:  # pragma: no cover
            ctypes.pointer(self._wd_addr.Flow)[0] = val

    @property
    def socket(self) -> Any | None:
        """The socket metadata (for Layer.SOCKET)."""
        return self._socket  # pragma: no cover

    @socket.setter
    def socket(self, val: Any | None) -> None:
        self._socket = val
        if self._layer == Layer.SOCKET and val is not None:  # pragma: no cover
            ctypes.pointer(self._wd_addr.Socket)[0] = val

    @property
    def reflect(self) -> Any | None:
        """The reflect metadata (for Layer.REFLECT)."""
        return self._reflect  # pragma: no cover

    @reflect.setter
    def reflect(self, val: Any | None) -> None:
        self._reflect = val
        if self._layer == Layer.REFLECT and val is not None:  # pragma: no cover
            ctypes.pointer(self._wd_addr.Reflect)[0] = val

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
        start: int = 40
        while proto in IPV6_EXT_HEADERS:
            if start >= len(self.raw):
                # less than two bytes left
                return None, None
            if proto == Protocol.FRAGMENT:
                hdrlen = 8
            elif proto == Protocol.AH:
                hdrlen = (self.raw[start + 1] + 2) * 4
            else:
                # Protocol.HOPOPT, Protocol.DSTOPTS, Protocol.ROUTING
                hdrlen = (self.raw[start + 1] + 1) * 8
            proto = self.raw[start]
            start += hdrlen
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

        if sys.platform != "win32":
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

    def _populate_wd_addr(self) -> None:
        """
        Populates the cached `WINDIVERT_ADDRESS` structure from scratch.
        """
        address = self._wd_addr
        address.Timestamp = self._timestamp
        address.Layer = self._layer
        address.Event = self._event
        address.Outbound = 1 if self._direction == Direction.OUTBOUND else 0
        address.Loopback = 1 if self._loopback else 0
        address.Impostor = 1 if self._impostor else 0
        address.Sniffed = 1 if self._sniffed else 0
        address.IPChecksum = 1 if self._ip_checksum else 0
        address.TCPChecksum = 1 if self._tcp_checksum else 0
        address.UDPChecksum = 1 if self._udp_checksum else 0

        # Zero-out the union to avoid stale data
        ctypes.memset(ctypes.byref(address, WinDivertAddress.u.offset), 0, WinDivertAddress.u.size)

        if self._layer in (Layer.NETWORK, Layer.NETWORK_FORWARD):
            address.Network.IfIdx, address.Network.SubIfIdx = self._interface
        elif self._layer == Layer.FLOW:
            if self._flow is not None:
                ctypes.pointer(address.Flow)[0] = self._flow
        elif self._layer == Layer.SOCKET:
            if self._socket is not None:
                ctypes.pointer(address.Socket)[0] = self._socket
        elif self._layer == Layer.REFLECT:
            if self._reflect is not None:
                ctypes.pointer(address.Reflect)[0] = self._reflect

    @property
    def wd_addr(self) -> WinDivertAddress:
        """
        Gets the address and metadata as a `WINDIVERT_ADDRESS` structure.
        :return: The `WINDIVERT_ADDRESS` structure.
        """
        return self._wd_addr

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
