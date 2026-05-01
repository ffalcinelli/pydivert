# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from __future__ import annotations

import ctypes
import logging
import socket
from pydivert.packet.header import Header

logger = logging.getLogger(__name__)

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

    def __init__(self, packet: Packet, start: int = 0) -> None:
        super().__init__(packet, start)
        self._view = self._struct_type.from_buffer(self._packet.raw, self._start)

    @property
    def src_addr(self) -> str | None:
        return socket.inet_ntop(self._af, bytes(self._view.saddr))

    @src_addr.setter
    def src_addr(self, val: str) -> None:
        addr_bytes = socket.inet_pton(self._af, val)
        for i, b in enumerate(addr_bytes):
            self._view.saddr[i] = b

    @property
    def dst_addr(self) -> str | None:
        return socket.inet_ntop(self._af, bytes(self._view.daddr))

    @dst_addr.setter
    def dst_addr(self, val: str) -> None:
        addr_bytes = socket.inet_pton(self._af, val)
        for i, b in enumerate(addr_bytes):
            self._view.daddr[i] = b

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
        self._view.v_ihl = (0x40 | (val & 0x0F))

    @property
    def header_len(self) -> int:
        return self.hdr_len * 4

    @property
    def tos(self) -> int: return self._view.tos
    @tos.setter
    def tos(self, val: int): self._view.tos = val

    @property
    def packet_len(self) -> int: return self._view.len
    @packet_len.setter
    def packet_len(self, val: int): self._view.len = val

    @property
    def ident(self) -> int: return self._view.id
    @ident.setter
    def ident(self, val: int): self._view.id = val

    @property
    def ttl(self) -> int: return self._view.ttl
    @ttl.setter
    def ttl(self, val: int): self._view.ttl = val

    @property
    def protocol(self) -> int: return self._view.proto
    @protocol.setter
    def protocol(self, val: int): self._view.proto = val

    @property
    def cksum(self) -> int: return self._view.check
    @cksum.setter
    def cksum(self, val: int): self._view.check = val

    @property
    def flags(self) -> int: return self._view.frag_off >> 13
    @flags.setter
    def flags(self, val: int):
        self._view.frag_off = (val << 13) | (self._view.frag_off & 0x1FFF)

    @property
    def frag_offset(self) -> int: return self._view.frag_off & 0x1FFF
    @frag_offset.setter
    def frag_offset(self, val: int):
        self._view.frag_off = (self._view.frag_off & 0xE000) | (val & 0x1FFF)

class IPv6Header(IPHeader):
    _struct_type = IPv6Struct
    _af = socket.AF_INET6
    header_len: int = 40
    __slots__ = ()
    __repr_fields__ = ("dst_addr", "hop_limit", "next_hdr", "payload_len", "src_addr")

    @property
    def payload_len(self) -> int: return self._view.payload_len
    @payload_len.setter
    def payload_len(self, val: int): self._view.payload_len = val

    @property
    def packet_len(self) -> int: return self.payload_len + 40
    @packet_len.setter
    def packet_len(self, val: int): self.payload_len = val - 40

    @property
    def next_hdr(self) -> int: return self._view.next_hdr
    @next_hdr.setter
    def next_hdr(self, val: int): self._view.next_hdr = val

    @property
    def hop_limit(self) -> int: return self._view.hop_limit
    @hop_limit.setter
    def hop_limit(self, val: int): self._view.hop_limit = val

    @property
    def traffic_class(self) -> int:
        return (self._view.v_tc_fl >> 20) & 0xFF
    
    @traffic_class.setter
    def traffic_class(self, val: int):
        self._view.v_tc_fl = (0x60000000 | (val << 20) | (self._view.v_tc_fl & 0x000FFFFF))
