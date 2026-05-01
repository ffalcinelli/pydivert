# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from __future__ import annotations

import ctypes
import pprint
import socket
from functools import cached_property
from typing import Any

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
        "_raw",
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
        "_wd_addr",
        "__dict__",  # Needed for cached_property
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
        # Ensure we have a writable bytearray
        if isinstance(raw, memoryview):
            raw = raw.tobytes()
        if not isinstance(raw, bytearray):
            raw = bytearray(raw)
        self._raw = raw

        if wd_addr is not None:
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

    @property
    def raw(self) -> memoryview:
        return memoryview(self._raw)

    @raw.setter
    def raw(self, val: bytes | bytearray | memoryview):
        if len(val) == len(self._raw):
            self._raw[:] = val
        else:
            self._raw = bytearray(val)
            # Clear caches since underlying buffer changed
            if hasattr(self, "__dict__"):
                self.__dict__.clear()

    @cached_property
    def address_family(self) -> int | None:
        if len(self._raw) >= 20:
            v = self._raw[0] >> 4
            if v == 4: return socket.AF_INET
            if v == 6: return socket.AF_INET6
        return None

    @cached_property
    def ipv4(self) -> IPv4Header | None:
        if self.address_family == socket.AF_INET:
            return IPv4Header(self)
        return None

    @cached_property
    def ipv6(self) -> IPv6Header | None:
        if self.address_family == socket.AF_INET6:
            return IPv6Header(self)
        return None

    @cached_property
    def ip(self) -> IPHeader | None:
        return self.ipv4 or self.ipv6

    @cached_property
    def protocol(self) -> tuple[int | None, int | None]:
        if self.ipv4:
            return self.ipv4.protocol, self.ipv4.header_len
        if self.ipv6:
            return self.ipv6.next_hdr, 40
        return None, None

    @cached_property
    def tcp(self) -> TCPHeader | None:
        proto, start = self.protocol
        if proto == Protocol.TCP and start is not None:
            return TCPHeader(self, start)
        return None

    @cached_property
    def udp(self) -> UDPHeader | None:
        proto, start = self.protocol
        if proto == Protocol.UDP and start is not None:
            return UDPHeader(self, start)
        return None

    @cached_property
    def icmpv4(self) -> ICMPv4Header | None:
        proto, start = self.protocol
        if proto == Protocol.ICMP and start is not None:
            return ICMPv4Header(self, start)
        return None

    @cached_property
    def icmpv6(self) -> ICMPv6Header | None:
        proto, start = self.protocol
        if proto == Protocol.ICMPV6 and start is not None:
            return ICMPv6Header(self, start)
        return None

    @property
    def src_addr(self) -> str | None: return self.ip.src_addr if self.ip else None
    @src_addr.setter
    def src_addr(self, val: str):
        if self.ip: self.ip.src_addr = val

    @property
    def dst_addr(self) -> str | None: return self.ip.dst_addr if self.ip else None
    @dst_addr.setter
    def dst_addr(self, val: str):
        if self.ip: self.ip.dst_addr = val

    @property
    def src_port(self) -> int | None:
        p = self.tcp or self.udp
        return p.src_port if p else None
    @src_port.setter
    def src_port(self, val: int):
        p = self.tcp or self.udp
        if p: p.src_port = val

    @property
    def dst_port(self) -> int | None:
        p = self.tcp or self.udp
        return p.dst_port if p else None
    @dst_port.setter
    def dst_port(self, val: int):
        p = self.tcp or self.udp
        if p: p.dst_port = val

    @property
    def payload(self) -> bytes | None:
        p = self.tcp or self.udp or self.icmpv4 or self.icmpv6
        return p.payload if p else None
    @payload.setter
    def payload(self, val: bytes | bytearray | memoryview):
        p = self.tcp or self.udp or self.icmpv4 or self.icmpv6
        if p: p.payload = val

    def _populate_wd_addr(self) -> None:
        address = self._wd_addr
        address.Timestamp = self._timestamp
        address.Layer = self._layer
        address.Event = self._event
        address.Outbound = 1 if self._direction == Direction.OUTBOUND else 0
        address.Loopback = 1 if self._loopback else 0
        address.Impostor = 1 if self._impostor else 0
        address.Sniffed = 1 if self._sniffed else 0

    @property
    def wd_addr(self) -> WinDivertAddress:
        return self._wd_addr

    def recalculate_checksums(self, flags: int = 0) -> int:
        import os
        if os.name != "nt":
            if self.ipv4:
                from pydivert.util import internet_checksum
                ihl = self.ipv4.hdr_len * 4
                self.ipv4.cksum = 0
                self.ipv4.cksum = internet_checksum(self._raw[:ihl])
                return 1
            return 0
        
        from pydivert import windivert_dll
        buff = (ctypes.c_char * len(self._raw)).from_buffer(self._raw)
        return windivert_dll.WinDivertHelperCalcChecksums(
            ctypes.byref(buff), len(self._raw), ctypes.byref(self.wd_addr), flags
        )
