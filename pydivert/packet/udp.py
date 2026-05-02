# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from __future__ import annotations

import ctypes
from pydivert.packet.header import Header, PayloadMixin, PortMixin

class UDPStruct(ctypes.BigEndianStructure):
    _fields_ = [
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("len", ctypes.c_uint16),
        ("check", ctypes.c_uint16),
    ]

class UDPHeader(Header, PayloadMixin, PortMixin):
    __slots__ = ("_view",)
    __match_args__ = ("src_port", "dst_port", "payload_len")
    __repr_fields__ = ("cksum", "dst_port", "header_len", "payload", "payload_len", "src_port")
    header_len: int = 8

    def __init__(self, packet: Packet, start: int = 0) -> None:
        super().__init__(packet, start)
        self._view = UDPStruct.from_buffer(self._packet._raw, self._start)

    @property
    def src_port(self) -> int: return self._view.sport
    @src_port.setter
    def src_port(self, val: int): self._view.sport = val

    @property
    def dst_port(self) -> int: return self._view.dport
    @dst_port.setter
    def dst_port(self, val: int): self._view.dport = val

    @property
    def payload_len(self) -> int: return self._view.len - 8
    @payload_len.setter
    def payload_len(self, val: int): self._view.len = val + 8

    @property
    def cksum(self) -> int: return self._view.check
    @cksum.setter
    def cksum(self, val: int): self._view.check = val

    @property
    def payload(self) -> bytes:
        return PayloadMixin.payload.fget(self)

    @payload.setter
    def payload(self, val: bytes | bytearray | memoryview) -> None:
        PayloadMixin.payload.fset(self, val)
        self.payload_len = len(val)
