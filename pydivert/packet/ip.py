# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from __future__ import annotations

import ctypes
import socket
from typing import TYPE_CHECKING

from pydivert.packet.header import Header

if TYPE_CHECKING:  # pragma: no cover
    from pydivert.packet import Packet


class IPv4Struct(ctypes.BigEndianStructure):
    _fields_ = [
        ("v_ihl", ctypes.c_uint8),
        ("tos", ctypes.c_uint8),
        ("len", ctypes.c_uint16),
        ("id", ctypes.c_uint16),
        ("frag_off", ctypes.c_uint16),
        ("ttl", ctypes.c_uint8),
        ("proto", ctypes.c_uint8),
        ("check", ctypes.c_uint16),
        ("saddr", ctypes.c_uint8 * 4),
        ("daddr", ctypes.c_uint8 * 4),
    ]


class IPv6Struct(ctypes.BigEndianStructure):
    _fields_ = [
        ("v_tc_fl", ctypes.c_uint32),
        ("payload_len", ctypes.c_uint16),
        ("next_hdr", ctypes.c_uint8),
        ("hop_limit", ctypes.c_uint8),
        ("saddr", ctypes.c_uint8 * 16),
        ("daddr", ctypes.c_uint8 * 16),
    ]


class IPHeader(Header):
    _struct_type: type[ctypes.BigEndianStructure]
    _af: int
    header_len: int
    __slots__ = ("_view",)

    def __init__(self, packet: Packet, start: int = 0) -> None:
        super().__init__(packet, start)
        # Use class attribute access to avoid AttributeError if accessed on parent
        struct_type = getattr(self, "_struct_type", None)
        if struct_type:
            try:
                self._view = struct_type.from_buffer(self._packet._raw, self._start)
            except ValueError:
                # Handle truncated header by using a zero-filled local structure
                self._view = struct_type()

    @property
    def packet_len(self) -> int:
        return len(self._packet.raw)

    @packet_len.setter
    def packet_len(self, val: int):
        raise AttributeError("can't set attribute")

    @property
    def src_addr(self) -> str | None:
        try:
            # Check if we have enough bytes for src address
            offset = 12 if self._af == socket.AF_INET else 8
            if len(self._packet.raw) < self._start + offset + (4 if self._af == socket.AF_INET else 16):
                return None
            return socket.inet_ntop(self._af, bytes(self._view.saddr))
        except (ValueError, OSError, AttributeError):
            return None

    @src_addr.setter
    def src_addr(self, val: str) -> None:
        addr_bytes = socket.inet_pton(self._af, val)
        for i, b in enumerate(addr_bytes):
            self._view.saddr[i] = b
        self._packet._invalidate_checksums()

    @property
    def dst_addr(self) -> str | None:
        try:
            # Check if we have enough bytes for dst address
            offset = 16 if self._af == socket.AF_INET else 24
            if len(self._packet.raw) < self._start + offset + (4 if self._af == socket.AF_INET else 16):
                return None
            return socket.inet_ntop(self._af, bytes(self._view.daddr))
        except (ValueError, OSError, AttributeError):
            return None

    @dst_addr.setter
    def dst_addr(self, val: str) -> None:
        addr_bytes = socket.inet_pton(self._af, val)
        for i, b in enumerate(addr_bytes):
            self._view.daddr[i] = b
        self._packet._invalidate_checksums()


class IPv4Header(IPHeader):
    _struct_type = IPv4Struct
    _af = socket.AF_INET
    __slots__ = ()
    __match_args__ = ("src_addr", "dst_addr", "protocol", "ident", "ttl")
    __repr_fields__ = ("cksum", "dst_addr", "ident", "packet_len", "protocol", "src_addr", "tos", "ttl")

    @property
    def hdr_len(self) -> int:
        return self._view.v_ihl & 0x0F

    @hdr_len.setter
    def hdr_len(self, val: int) -> None:
        if not (5 <= val <= 15):
            raise ValueError("IP header length must be between 5 and 15")
        self._view.v_ihl = 0x40 | (val & 0x0F)
        self._packet._invalidate_checksums()

    @property
    def header_len(self) -> int:
        return self.hdr_len * 4

    @property
    def tos(self) -> int:
        return self._view.tos

    @tos.setter
    def tos(self, val: int):
        self._view.tos = val
        self._packet._invalidate_checksums()

    @property
    def diff_serv(self) -> int:
        return self.tos >> 2

    @diff_serv.setter
    def diff_serv(self, val: int):
        self.tos = (val << 2) | self.ecn

    @property
    def dscp(self) -> int:
        return self.diff_serv

    @dscp.setter
    def dscp(self, val: int):
        self.diff_serv = val

    @property
    def ecn(self) -> int:
        return self.tos & 0x03

    @ecn.setter
    def ecn(self, val: int):
        self.tos = (self.diff_serv << 2) | (val & 0x03)

    @property
    def packet_len(self) -> int:
        return self._view.len

    @packet_len.setter
    def packet_len(self, val: int):
        self._view.len = val
        self._packet._invalidate_checksums()

    @property
    def ident(self) -> int:
        return self._view.id

    @ident.setter
    def ident(self, val: int):
        self._view.id = val
        self._packet._invalidate_checksums()

    @property
    def ttl(self) -> int:
        return self._view.ttl

    @ttl.setter
    def ttl(self, val: int):
        self._view.ttl = val
        self._packet._invalidate_checksums()

    @property
    def protocol(self) -> int:
        return self._view.proto

    @protocol.setter
    def protocol(self, val: int):
        self._view.proto = val
        self._packet._invalidate_checksums()

    @property
    def cksum(self) -> int:
        return self._view.check

    @cksum.setter
    def cksum(self, val: int):
        self._view.check = val

    @property
    def flags(self) -> int:
        return self._view.frag_off >> 13

    @flags.setter
    def flags(self, val: int):
        self._view.frag_off = (val << 13) | (self._view.frag_off & 0x1FFF)
        self._packet._invalidate_checksums()

    @property
    def frag_offset(self) -> int:
        return self._view.frag_off & 0x1FFF

    @frag_offset.setter
    def frag_offset(self, val: int):
        self._view.frag_off = (self._view.frag_off & 0xE000) | (val & 0x1FFF)
        self._packet._invalidate_checksums()

    @property
    def rf(self) -> bool:
        return bool(self._view.frag_off & 0x8000)

    @rf.setter
    def rf(self, val: bool):
        if val:
            self._view.frag_off |= 0x8000
        else:
            self._view.frag_off &= ~0x8000
        self._packet._invalidate_checksums()

    @property
    def evil(self) -> bool:
        return self.rf

    @evil.setter
    def evil(self, val: bool):
        self.rf = val

    @property
    def reserved(self) -> bool:
        return self.rf

    @reserved.setter
    def reserved(self, val: bool):
        self.rf = val

    @property
    def df(self) -> bool:
        return bool(self._view.frag_off & 0x4000)

    @df.setter
    def df(self, val: bool):
        if val:
            self._view.frag_off |= 0x4000
        else:
            self._view.frag_off &= ~0x4000
        self._packet._invalidate_checksums()

    @property
    def mf(self) -> bool:
        return bool(self._view.frag_off & 0x2000)

    @mf.setter
    def mf(self, val: bool):
        if val:
            self._view.frag_off |= 0x2000
        else:
            self._view.frag_off &= ~0x2000
        self._packet._invalidate_checksums()


class IPv6Header(IPHeader):
    _struct_type = IPv6Struct
    _af = socket.AF_INET6
    header_len: int = 40
    __slots__ = ()
    __repr_fields__ = ("dst_addr", "hop_limit", "next_hdr", "payload_len", "src_addr")

    @property
    def payload_len(self) -> int:
        return self._view.payload_len

    @payload_len.setter
    def payload_len(self, val: int):
        self._view.payload_len = val
        self._packet._invalidate_checksums()

    @property
    def packet_len(self) -> int:
        return self.payload_len + 40

    @packet_len.setter
    def packet_len(self, val: int):
        self.payload_len = val - 40

    @property
    def next_hdr(self) -> int:
        return self._view.next_hdr

    @next_hdr.setter
    def next_hdr(self, val: int):
        self._view.next_hdr = val
        self._packet._invalidate_checksums()

    @property
    def hop_limit(self) -> int:
        return self._view.hop_limit

    @hop_limit.setter
    def hop_limit(self, val: int):
        self._view.hop_limit = val
        self._packet._invalidate_checksums()

    @property
    def traffic_class(self) -> int:
        return (self._view.v_tc_fl >> 20) & 0xFF

    @traffic_class.setter
    def traffic_class(self, val: int):
        self._view.v_tc_fl = 0x60000000 | (val << 20) | (self._view.v_tc_fl & 0x000FFFFF)
        self._packet._invalidate_checksums()

    @property
    def flow_label(self) -> int:
        return self._view.v_tc_fl & 0x000FFFFF

    @flow_label.setter
    def flow_label(self, val: int):
        self._view.v_tc_fl = (self._view.v_tc_fl & 0xFFF00000) | (val & 0x000FFFFF)
        self._packet._invalidate_checksums()

    @property
    def ecn(self) -> int:
        return self.traffic_class & 0x03

    @ecn.setter
    def ecn(self, val: int):
        self.traffic_class = (self.diff_serv << 2) | (val & 0x03)

    @property
    def diff_serv(self) -> int:
        return self.traffic_class >> 2

    @diff_serv.setter
    def diff_serv(self, val: int):
        self.traffic_class = (val << 2) | self.ecn

    @property
    def dscp(self) -> int:
        return self.diff_serv

    @dscp.setter
    def dscp(self, val: int):
        self.diff_serv = val
