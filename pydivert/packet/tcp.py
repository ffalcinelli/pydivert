# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from __future__ import annotations

import ctypes
from pydivert.packet.header import Header, PayloadMixin, PortMixin

class TCPStruct(ctypes.BigEndianStructure):
    _fields_ = [
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("seq", ctypes.c_uint32),
        ("ack", ctypes.c_uint32),
        ("off_res_flags", ctypes.c_uint16),
        ("win", ctypes.c_uint16),
        ("check", ctypes.c_uint16),
        ("urg", ctypes.c_uint16),
    ]

class TCPHeader(Header, PayloadMixin, PortMixin):
    __slots__ = ("_view",)
    __match_args__ = ("src_port", "dst_port", "seq_num", "ack_num", "control_bits")
    __repr_fields__ = ("ack", "ack_num", "cksum", "control_bits", "data_offset", "dst_port", "header_len", "payload", "seq_num", "src_port", "window_size")

    def __init__(self, packet: Packet, start: int = 0) -> None:
        super().__init__(packet, start)
        self._view = TCPStruct.from_buffer(self._packet.raw, self._start)

    @property
    def src_port(self) -> int: return self._view.sport
    @src_port.setter
    def src_port(self, val: int): self._view.sport = val

    @property
    def dst_port(self) -> int: return self._view.dport
    @dst_port.setter
    def dst_port(self, val: int): self._view.dport = val

    @property
    def seq_num(self) -> int: return self._view.seq
    @seq_num.setter
    def seq_num(self, val: int): self._view.seq = val

    @property
    def ack_num(self) -> int: return self._view.ack
    @ack_num.setter
    def ack_num(self, val: int): self._view.ack = val

    @property
    def data_offset(self) -> int: return self._view.off_res_flags >> 12
    @data_offset.setter
    def data_offset(self, val: int):
        self._view.off_res_flags = (val << 12) | (self._view.off_res_flags & 0x0FFF)

    @property
    def header_len(self) -> int: return self.data_offset * 4

    @property
    def control_bits(self) -> int: return self._view.off_res_flags & 0x01FF
    @control_bits.setter
    def control_bits(self, val: int):
        self._view.off_res_flags = (self._view.off_res_flags & 0xFE00) | (val & 0x01FF)

    @property
    def window_size(self) -> int: return self._view.win
    @window_size.setter
    def window_size(self, val: int): self._view.win = val

    @property
    def cksum(self) -> int: return self._view.check
    @cksum.setter
    def cksum(self, val: int): self._view.check = val

    @property
    def urg_ptr(self) -> int: return self._view.urg
    @urg_ptr.setter
    def urg_ptr(self, val: int): self._view.urg = val

    # Flags
    @property
    def syn(self) -> bool: return bool(self.control_bits & 0x02)
    @syn.setter
    def syn(self, val: bool):
        if val: self.control_bits |= 0x02
        else: self.control_bits &= ~0x02

    @property
    def ack(self) -> bool: return bool(self.control_bits & 0x10)
    @ack.setter
    def ack(self, val: bool):
        if val: self.control_bits |= 0x10
        else: self.control_bits &= ~0x10

    @property
    def fin(self) -> bool: return bool(self.control_bits & 0x01)
    @fin.setter
    def fin(self, val: bool):
        if val: self.control_bits |= 0x01
        else: self.control_bits &= ~0x01

    @property
    def rst(self) -> bool: return bool(self.control_bits & 0x04)
    @rst.setter
    def rst(self, val: bool):
        if val: self.control_bits |= 0x04
        else: self.control_bits &= ~0x04

    @property
    def psh(self) -> bool: return bool(self.control_bits & 0x08)
    @psh.setter
    def psh(self, val: bool):
        if val: self.control_bits |= 0x08
        else: self.control_bits &= ~0x08

    @property
    def urg(self) -> bool: return bool(self.control_bits & 0x20)
    @urg.setter
    def urg(self, val: bool):
        if val: self.control_bits |= 0x20
        else: self.control_bits &= ~0x20
