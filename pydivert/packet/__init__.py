# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from __future__ import annotations

import ctypes
import pprint
import socket
import struct
import threading
from functools import cached_property
from typing import Any

from pydivert.consts import Direction, Layer, Protocol
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
        "_icmp_checksum",
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
            self._interface = (wd_addr.u.Network.IfIdx, wd_addr.u.Network.SubIfIdx)
            self._direction = Direction.OUTBOUND if wd_addr.Outbound else Direction.INBOUND
            self._timestamp = wd_addr.Timestamp
            self._loopback = bool(wd_addr.Loopback)
            self._impostor = bool(wd_addr.Impostor)
            self._sniffed = bool(wd_addr.Sniffed)
            self._ip_checksum = bool(wd_addr.IPChecksum)
            self._tcp_checksum = bool(wd_addr.TCPChecksum)
            self._udp_checksum = bool(wd_addr.UDPChecksum)
            self._icmp_checksum = True # WinDivert doesn't have a separate ICMP flag, assume True
            self._layer = wd_addr.Layer
            self._event = wd_addr.Event
            self._flow = wd_addr.u.Flow if self._layer == Layer.FLOW else None
            self._socket = wd_addr.u.Socket if self._layer == Layer.SOCKET else None
            self._reflect = wd_addr.u.Reflect if self._layer == Layer.REFLECT else None
        else:
            if isinstance(interface, int):
                self._interface = (interface, 0)
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
            self._icmp_checksum = False
            self._layer = layer
            self._event = event
            self._flow = flow
            self._socket = socket
            self._reflect = reflect
            self._wd_addr = WinDivertAddress()
            self._populate_wd_addr()

    def __repr__(self) -> str:
        return f'<Packet {self.protocol[0]} from={self.src_addr}:{self.src_port} to={self.dst_addr}:{self.dst_port} len={len(self.raw)}>'

    @property
    def raw(self) -> memoryview:
        """The raw packet data."""
        return memoryview(self._raw)

    @raw.setter
    def raw(self, val: bytes | bytearray | memoryview):
        if isinstance(val, memoryview):
            val = val.tobytes()
        if not isinstance(val, bytearray):
            val = bytearray(val)
        self._raw = val
        # Clear caches since underlying buffer changed
        if hasattr(self, "__dict__"):
            self.__dict__.clear()
        self._invalidate_checksums()

    @cached_property
    def address_family(self) -> int | None:
        """The address family of the IP header (AF_INET or AF_INET6)."""
        if len(self._raw) >= 20:
            version = self._raw[0] >> 4
            if version == 4:
                return socket.AF_INET
            if version == 6:
                return socket.AF_INET6
        return None

    @cached_property
    def ipv4(self) -> IPv4Header | None:
        """The IPv4 header (if present)."""
        if len(self._raw) >= 1 and (self._raw[0] & 0xF0) == 0x40:
            return IPv4Header(self)
        return None

    @cached_property
    def ipv6(self) -> IPv6Header | None:
        """The IPv6 header (if present)."""
        if len(self._raw) >= 1 and (self._raw[0] & 0xF0) == 0x60:
            return IPv6Header(self)
        return None

    @cached_property
    def ip(self) -> IPHeader | None:
        """Convenience property for ipv4 or ipv6."""
        return self.ipv4 or self.ipv6

    @cached_property
    def protocol(self) -> tuple[int | None, int | None]:
        if self.ipv4:
            return self.ipv4.protocol, self.ipv4.header_len
        if self.ipv6:
            proto = self.ipv6.next_hdr
            offset = 40
            # Extension headers that have a 'next header' field and follow RFC 2460 / 4302
            # 0: Hop-by-Hop, 43: Routing, 44: Fragment, 51: AH, 60: Destination Options
            while proto in (0, 43, 44, 51, 60):
                if len(self._raw) < offset + 2:
                    break
                next_proto = self._raw[offset]
                if proto == 44: # Fragment Header is fixed 8 bytes
                    hdr_len = 8
                elif proto == 51: # AH Header length is in 4-byte units, -2
                    hdr_len = (self._raw[offset + 1] + 2) * 4
                else: # Others use 8-byte units
                    hdr_len = (self._raw[offset + 1] + 1) * 8

                proto = next_proto
                offset += hdr_len
            return proto, offset
        return None, None

    @cached_property
    def tcp(self) -> TCPHeader | None:
        """The TCP header (if present)."""
        proto, start = self.protocol
        if proto == Protocol.TCP and start is not None:
            return TCPHeader(self, start)
        return None

    @cached_property
    def udp(self) -> UDPHeader | None:
        """The UDP header (if present)."""
        proto, start = self.protocol
        if proto == Protocol.UDP and start is not None:
            return UDPHeader(self, start)
        return None

    @cached_property
    def icmpv4(self) -> ICMPv4Header | None:
        """The ICMPv4 header (if present)."""
        proto, start = self.protocol
        if proto == Protocol.ICMP and start is not None:
            return ICMPv4Header(self, start)
        return None

    @cached_property
    def icmpv6(self) -> ICMPv6Header | None:
        """The ICMPv6 header (if present)."""
        proto, start = self.protocol
        if proto == Protocol.ICMPV6 and start is not None:
            return ICMPv6Header(self, start)
        return None

    @cached_property
    def icmp(self) -> ICMPHeader | None:
        """Convenience property for icmpv4 or icmpv6."""
        return self.icmpv4 or self.icmpv6

    @property
    def interface(self) -> tuple[int, int]:
        """The interface index and sub-interface index (if any)."""
        return self._interface

    @interface.setter
    def interface(self, val: tuple[int, int]) -> None:
        self._interface = val
        if self._layer in (Layer.NETWORK, Layer.NETWORK_FORWARD):
            self._wd_addr.u.Network.IfIdx, self._wd_addr.u.Network.SubIfIdx = val

    @property
    def direction(self) -> Direction:
        """The packet direction (INBOUND or OUTBOUND)."""
        return self._direction

    @direction.setter
    def direction(self, val: Direction) -> None:
        self._direction = val
        self._wd_addr.Outbound = 1 if val == Direction.OUTBOUND else 0

    @property
    def timestamp(self) -> int:
        """The packet timestamp."""
        return self._timestamp

    @timestamp.setter
    def timestamp(self, val: int) -> None:
        self._timestamp = val
        self._wd_addr.Timestamp = val

    @property
    def is_loopback(self) -> bool:
        """True if the packet was captured on the loopback interface."""
        return self._loopback

    @is_loopback.setter
    def is_loopback(self, val: bool) -> None:
        self._loopback = val
        self._wd_addr.Loopback = 1 if val else 0

    @property
    def loopback(self) -> bool: return self.is_loopback
    @loopback.setter
    def loopback(self, val: bool) -> None: self.is_loopback = val

    @property
    def is_impostor(self) -> bool:
        """True if the packet is an impostor."""
        return self._impostor

    @is_impostor.setter
    def is_impostor(self, val: bool) -> None:
        self._impostor = val
        self._wd_addr.Impostor = 1 if val else 0

    @property
    def impostor(self) -> bool: return self.is_impostor
    @impostor.setter
    def impostor(self, val: bool) -> None: self.is_impostor = val

    @property
    def is_sniffed(self) -> bool:
        """True if the packet was sniffed."""
        return self._sniffed

    @is_sniffed.setter
    def is_sniffed(self, val: bool) -> None:
        self._sniffed = val
        self._wd_addr.Sniffed = 1 if val else 0

    @property
    def sniffed(self) -> bool: return self.is_sniffed
    @sniffed.setter
    def sniffed(self, val: bool) -> None: self.is_sniffed = val

    @property
    def is_inbound(self) -> bool:
        """True if the packet is inbound."""
        return self._direction == Direction.INBOUND

    @is_inbound.setter
    def is_inbound(self, val: bool) -> None:
        self.direction = Direction.INBOUND if val else Direction.OUTBOUND

    @property
    def is_outbound(self) -> bool:
        """True if the packet is outbound."""
        return self._direction == Direction.OUTBOUND

    @is_outbound.setter
    def is_outbound(self, val: bool) -> None:
        self.direction = Direction.OUTBOUND if val else Direction.INBOUND

    @property
    def layer(self) -> Layer:
        """The WinDivert layer."""
        return self._layer

    @layer.setter
    def layer(self, val: Layer) -> None:
        self._layer = val
        self._wd_addr.Layer = val
        # Clear union when layer changes
        import ctypes
        ctypes.memset(ctypes.byref(self._wd_addr.u), 0, ctypes.sizeof(self._wd_addr.u))
        # Sync back the relevant fields for the new layer
        if val in (Layer.NETWORK, Layer.NETWORK_FORWARD):
            self._wd_addr.u.Network.IfIdx, self._wd_addr.u.Network.SubIfIdx = self._interface
        elif val == Layer.FLOW and self._flow:
            self._wd_addr.u.Flow = self._flow
        elif val == Layer.SOCKET and self._socket:
            self._wd_addr.u.Socket = self._socket
        elif val == Layer.REFLECT and self._reflect:
            self._wd_addr.u.Reflect = self._reflect

    @property
    def event(self) -> Any:
        """The WinDivert event."""
        return self._event

    @event.setter
    def event(self, val: Any) -> None:
        self._event = val
        self._wd_addr.Event = val

    @property
    def flow(self) -> Any | None:
        """The flow data (if Layer.FLOW)."""
        return self._flow

    @flow.setter
    def flow(self, val: Any) -> None:
        self._flow = val
        if val is not None and self._layer == Layer.FLOW:
            self._wd_addr.u.Flow = val

    @property
    def socket(self) -> Any | None:
        """The socket data (if Layer.SOCKET)."""
        return self._socket

    @socket.setter
    def socket(self, val: Any) -> None:
        self._socket = val
        if val is not None and self._layer == Layer.SOCKET:
            self._wd_addr.u.Socket = val

    @property
    def reflect(self) -> Any | None:
        """The REFLECT metadata."""
        return self._reflect

    @reflect.setter
    def reflect(self, val: Any) -> None:
        self._reflect = val
        if val is not None and self._layer == Layer.REFLECT:
            self._wd_addr.u.Reflect = val

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

    @property
    def ip_checksum(self) -> bool:
        """True if the IP checksum is valid."""
        import os
        if os.name != "nt" and self.ipv4:
            from pydivert.util import internet_checksum
            ihl = self.ipv4.hdr_len * 4
            return internet_checksum(self._raw[:ihl]) == 0
        return self._ip_checksum or bool(self._wd_addr.IPChecksum)

    @ip_checksum.setter
    def ip_checksum(self, val: bool) -> None:
        self._ip_checksum = val
        self._wd_addr.IPChecksum = 1 if val else 0

    @property
    def tcp_checksum(self) -> bool:
        """True if the TCP checksum is valid."""
        import os
        if os.name == "nt":
            return self._tcp_checksum or bool(self._wd_addr.TCPChecksum)
        return self._tcp_checksum

    @tcp_checksum.setter
    def tcp_checksum(self, val: bool) -> None:
        self._tcp_checksum = val
        self._wd_addr.TCPChecksum = 1 if val else 0

    @property
    def udp_checksum(self) -> bool:
        """True if the UDP checksum is valid."""
        import os
        if os.name == "nt":
            return self._udp_checksum or bool(self._wd_addr.UDPChecksum)
        return self._udp_checksum

    @udp_checksum.setter
    def udp_checksum(self, val: bool) -> None:
        self._udp_checksum = val
        self._wd_addr.UDPChecksum = 1 if val else 0

    @property
    def icmp_checksum(self) -> bool:
        """True if the ICMP checksum is valid."""
        from pydivert.util import internet_checksum
        if self.icmp:
            return internet_checksum(self.icmp.raw) == 0
        return self._icmp_checksum

    @icmp_checksum.setter
    def icmp_checksum(self, val: bool) -> None:
        self._icmp_checksum = val

    def _invalidate_checksums(self):
        """Invalidate all checksum flags."""
        self._ip_checksum = False
        self._tcp_checksum = False
        self._udp_checksum = False
        self._icmp_checksum = False
        self._wd_addr.IPChecksum = 0
        self._wd_addr.TCPChecksum = 0
        self._wd_addr.UDPChecksum = 0

    @property
    def is_checksum_valid(self) -> bool:
        """True if all present checksums are valid."""
        import os
        if os.name == "nt":
            # On Windows, we trust the flags in wd_addr or our internal ones
            res = True
            if self.ipv4: res &= (self._ip_checksum or bool(self._wd_addr.IPChecksum))
            if self.tcp: res &= (self._tcp_checksum or bool(self._wd_addr.TCPChecksum))
            if self.udp: res &= (self._udp_checksum or bool(self._wd_addr.UDPChecksum))
            if self.icmp: res &= self.icmp_checksum
            return res

        # On Linux/Other, we check our internal flags
        res = True
        if self.ipv4: res &= self._ip_checksum
        if self.tcp: res &= self._tcp_checksum
        if self.udp: res &= self._udp_checksum
        if self.icmp: res &= self.icmp_checksum
        return res

    def matches(self, filter_str: str) -> bool:
        """
        Returns True if the packet matches the given filter string.
        (Only supported on Windows)
        """
        import sys
        if sys.platform != "win32":
            raise NotImplementedError("matches() is only supported on Windows.")
        self._populate_wd_addr()
        from pydivert.windivert_dll import WinDivertHelperEvalFilter

        # Ensure we have a valid buffer and address
        buff = (ctypes.c_char * len(self._raw)).from_buffer(self._raw)
        addr = self._wd_addr
        # Ensure null-termination and correct encoding
        f_bytes = filter_str.encode("ascii") + b"\0"
        return bool(WinDivertHelperEvalFilter(f_bytes, ctypes.cast(buff, ctypes.c_void_p), len(self._raw), ctypes.byref(addr)))

    def _populate_wd_addr(self) -> None:
        address = self._wd_addr
        address.Timestamp = self._timestamp
        address.Layer = self._layer
        address.Event = self._event
        address.Outbound = 1 if self._direction == Direction.OUTBOUND else 0
        address.Loopback = 1 if self._loopback else 0
        address.Impostor = 1 if self._impostor else 0
        address.Sniffed = 1 if self._sniffed else 0

        if self._layer in (Layer.NETWORK, Layer.NETWORK_FORWARD):
            address.u.Network.IfIdx, address.u.Network.SubIfIdx = self._interface
        elif self._layer == Layer.FLOW and self._flow:
            address.u.Flow = self._flow
        elif self._layer == Layer.SOCKET and self._socket:
            address.u.Socket = self._socket
        elif self._layer == Layer.REFLECT and self._reflect:
            address.u.Reflect = self._reflect

        address.IPChecksum = 1 if self._ip_checksum else 0
        address.TCPChecksum = 1 if self._tcp_checksum else 0
        address.UDPChecksum = 1 if self._udp_checksum else 0

    @property
    def wd_addr(self) -> WinDivertAddress:
        return self._wd_addr

    def recalculate_checksums(self, flags: int = 0) -> int:
        import os
        if os.name != "nt":
            # Recalculate all present checksums
            count = 0
            from pydivert.util import internet_checksum
            if self.ipv4:
                ihl = self.ipv4.hdr_len * 4
                self.ipv4.cksum = 0
                self.ipv4.cksum = internet_checksum(self._raw[:ihl])
                self._ip_checksum = True
                count += 1

            if self.icmp:
                self.icmp.cksum = 0
                self.icmp.cksum = internet_checksum(self.icmp.raw)
                self._icmp_checksum = True # Even if not explicitly checked in is_checksum_valid yet
                count += 1

            # For TCP/UDP we need pseudo-header logic.
            import socket
            l4 = self.tcp or self.udp
            if l4:
                l4.cksum = 0
                proto = 6 if self.tcp else 17
                pseudo_header = b""
                if self.ipv4:
                    src = socket.inet_aton(self.src_addr)
                    dst = socket.inet_aton(self.dst_addr)
                    pseudo_header = struct.pack("!4s4sBBH", src, dst, 0, proto, len(l4.raw))
                elif self.ipv6:
                    src = socket.inet_pton(socket.AF_INET6, self.src_addr)
                    dst = socket.inet_pton(socket.AF_INET6, self.dst_addr)
                    # IPv6 pseudo-header: [Source, Dest, Length (u32), Zeros (u24), NextHeader (u8)]
                    pseudo_header = src + dst + struct.pack("!I3xB", len(l4.raw), proto)

                l4.cksum = internet_checksum(pseudo_header + l4.raw)
                if self.tcp: self._tcp_checksum = True
                else: self._udp_checksum = True
                count += 1
            return count

        self._populate_wd_addr()
        from pydivert import windivert_dll
        buff = (ctypes.c_char * len(self._raw)).from_buffer(self._raw)
        addr = self._wd_addr
        # Set checksum flags so the helper knows what to calculate
        addr.IPChecksum = 1
        addr.TCPChecksum = 1
        addr.UDPChecksum = 1
        res = windivert_dll.WinDivertHelperCalcChecksums(
            ctypes.byref(buff), len(self._raw), ctypes.byref(addr), flags
        )
        if res:
            self._ip_checksum = bool(addr.IPChecksum) or (res > 0)
            self._tcp_checksum = bool(addr.TCPChecksum) or (res > 0)
            self._udp_checksum = bool(addr.UDPChecksum) or (res > 0)
            self._icmp_checksum = True
            # Also sync back to addr for good measure
            addr.IPChecksum = 1
            addr.TCPChecksum = 1
            addr.UDPChecksum = 1
        return res
