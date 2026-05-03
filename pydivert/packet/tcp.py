# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING

from pydivert.packet.header import Header, PayloadMixin, PortMixin

if TYPE_CHECKING:  # pragma: no cover
    from pydivert.packet import Packet


class TCPStruct(ctypes.BigEndianStructure):
    _fields_ = [
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("seq", ctypes.c_uint32),
        ("ack", ctypes.c_uint32),
        ("off_res_flags", ctypes.c_uint16),
        ("win", ctypes.c_uint16),
        ("check", ctypes.c_uint16),
        ("urg_ptr", ctypes.c_uint16),
    ]


class TCPHeader(Header, PortMixin, PayloadMixin):
    __slots__ = ("_view",)
    __match_args__ = ("src_port", "dst_port", "seq_num", "ack_num", "control_bits")
    __repr_fields__ = ("ack_num", "cksum", "control_bits", "data_offset", "dst_port", "header_len", "payload", "payload_len", "seq_num", "src_port", "window")

    def __init__(self, packet: Packet, start: int = 0) -> None:
        super().__init__(packet, start)
        try:
            self._view = TCPStruct.from_buffer(self._packet._raw, self._start)
        except ValueError:
            self._view = TCPStruct()

    @property
    def src_port(self) -> int: return self._view.sport
    @src_port.setter
    def src_port(self, val: int):
        self._view.sport = val
        self._packet._invalidate_checksums()

    @property
    def dst_port(self) -> int: return self._view.dport
    @dst_port.setter
    def dst_port(self, val: int):
        self._view.dport = val
        self._packet._invalidate_checksums()

    @property
    def seq_num(self) -> int: return self._view.seq
    @seq_num.setter
    def seq_num(self, val: int):
        self._view.seq = val
        self._packet._invalidate_checksums()

    @property
    def ack_num(self) -> int: return self._view.ack
    @ack_num.setter
    def ack_num(self, val: int):
        self._view.ack = val
        self._packet._invalidate_checksums()

    @property
    def data_offset(self) -> int: return self._view.off_res_flags >> 12
    @data_offset.setter
    def data_offset(self, val: int):
        if not (5 <= val <= 15):
            raise ValueError("TCP data offset must be between 5 and 15")
        self._view.off_res_flags = (val << 12) | (self._view.off_res_flags & 0x0FFF)
        self._packet._invalidate_checksums()

    @property
    def reserved(self) -> int:
        return (self._view.off_res_flags >> 9) & 0x07

    @reserved.setter
    def reserved(self, val: int):
        self._view.off_res_flags = ((self.data_offset << 12) | 
                                    ((val & 0x07) << 9) | 
                                    (self.control_bits))
        self._packet._invalidate_checksums()

    @property
    def control_bits(self) -> int:
        return self._view.off_res_flags & 0x01FF

    @control_bits.setter
    def control_bits(self, val: int):
        self._view.off_res_flags = (self._view.off_res_flags & 0xFE00) | (val & 0x01FF)
        self._packet._invalidate_checksums()

    @property
    def ns(self) -> bool: return bool(self._view.off_res_flags & 0x0100)
    @ns.setter
    def ns(self, val: bool):
        if val: self._view.off_res_flags |= 0x0100
        else: self._view.off_res_flags &= ~0x0100
        self._packet._invalidate_checksums()

    @property
    def cwr(self) -> bool: return bool(self._view.off_res_flags & 0x0080)
    @cwr.setter
    def cwr(self, val: bool):
        if val: self._view.off_res_flags |= 0x0080
        else: self._view.off_res_flags &= ~0x0080
        self._packet._invalidate_checksums()

    @property
    def ece(self) -> bool: return bool(self._view.off_res_flags & 0x0040)
    @ece.setter
    def ece(self, val: bool):
        if val: self._view.off_res_flags |= 0x0040
        else: self._view.off_res_flags &= ~0x0040
        self._packet._invalidate_checksums()

    @property
    def urg(self) -> bool: return bool(self._view.off_res_flags & 0x0020)
    @urg.setter
    def urg(self, val: bool):
        if val: self._view.off_res_flags |= 0x0020
        else: self._view.off_res_flags &= ~0x0020
        self._packet._invalidate_checksums()

    @property
    def ack(self) -> bool: return bool(self._view.off_res_flags & 0x0010)
    @ack.setter
    def ack(self, val: bool):
        if val: self._view.off_res_flags |= 0x0010
        else: self._view.off_res_flags &= ~0x0010
        self._packet._invalidate_checksums()

    @property
    def psh(self) -> bool: return bool(self._view.off_res_flags & 0x0008)
    @psh.setter
    def psh(self, val: bool):
        if val: self._view.off_res_flags |= 0x0008
        else: self._view.off_res_flags &= ~0x0008
        self._packet._invalidate_checksums()

    @property
    def rst(self) -> bool: return bool(self._view.off_res_flags & 0x0004)
    @rst.setter
    def rst(self, val: bool):
        if val: self._view.off_res_flags |= 0x0004
        else: self._view.off_res_flags &= ~0x0004
        self._packet._invalidate_checksums()

    @property
    def syn(self) -> bool: return bool(self._view.off_res_flags & 0x0002)
    @syn.setter
    def syn(self, val: bool):
        if val: self._view.off_res_flags |= 0x0002
        else: self._view.off_res_flags &= ~0x0002
        self._packet._invalidate_checksums()

    @property
    def fin(self) -> bool: return bool(self._view.off_res_flags & 0x0001)
    @fin.setter
    def fin(self, val: bool):
        if val: self._view.off_res_flags |= 0x0001
        else: self._view.off_res_flags &= ~0x0001
        self._packet._invalidate_checksums()

    @property
    def window(self) -> int: return self._view.win
    @window.setter
    def window(self, val: int):
        self._view.win = val
        self._packet._invalidate_checksums()

    @property
    def cksum(self) -> int: return self._view.check
    @cksum.setter
    def cksum(self, val: int): self._view.check = val

    @property
    def urg_ptr(self) -> int: return self._view.urg_ptr
    @urg_ptr.setter
    def urg_ptr(self, val: int):
        self._view.urg_ptr = val
        self._packet._invalidate_checksums()

    @property
    def header_len(self) -> int:
        return self.data_offset * 4

    @property
    def payload_len(self) -> int:
        if self._packet.ipv4:
            return self._packet.ipv4.packet_len - self._packet.ipv4.header_len - self.header_len
        if self._packet.ipv6:
            return self._packet.ipv6.payload_len - (self._start - 40) - self.header_len
        return len(self._packet.raw) - self._start - self.header_len

    @payload_len.setter
    def payload_len(self, val: int):
        # We can't easily change the packet length from here without modifying IP header too.
        # But we can update the data_offset if we wanted to (unlikely).
        pass
