# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from __future__ import annotations

import ctypes
from pydivert.packet.header import Header, PayloadMixin

class ICMPStruct(ctypes.BigEndianStructure):
    _fields_ = [
        ("type", ctypes.c_uint8),
        ("code", ctypes.c_uint8),
        ("check", ctypes.c_uint16),
    ]

class ICMPHeader(Header, PayloadMixin):
    __slots__ = ("_view",)
    __match_args__ = ("type", "code", "cksum")
    __repr_fields__ = ("cksum", "code", "header_len", "payload", "type")

    def __init__(self, packet: Packet, start: int = 0) -> None:
        super().__init__(packet, start)
        self._view = ICMPStruct.from_buffer(self._packet._raw, self._start)

    @property
    def type(self) -> int: return self._view.type
    @type.setter
    def type(self, val: int): self._view.type = val

    @property
    def code(self) -> int: return self._view.code
    @code.setter
    def code(self, val: int): self._view.code = val

    @property
    def cksum(self) -> int: return self._view.check
    @cksum.setter
    def cksum(self, val: int): self._view.check = val

class ICMPv4Header(ICMPHeader):
    __slots__ = ()
    header_len: int = 4

class ICMPv6Header(ICMPHeader):
    header_len: int = 4
