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

import struct

from pydivert.packet.header import Header, PayloadMixin, PortMixin
from pydivert.util import flag_property, raw_property


class TCPHeader(Header, PayloadMixin, PortMixin):
    __slots__ = ()
    __repr_fields__ = (
        "ack",
        "ack_num",
        "cksum",
        "control_bits",
        "cwr",
        "data_offset",
        "dst_port",
        "ece",
        "fin",
        "header_len",
        "ns",
        "payload",
        "psh",
        "raw",
        "reserved",
        "rst",
        "seq_num",
        "src_port",
        "syn",
        "urg",
        "urg_ptr",
        "window_size",
    )
    ns: bool = flag_property("ns", 12, 0b00000001)  # type: ignore[assignment]

    cwr: bool = flag_property("cwr", 13, 0b10000000)  # type: ignore[assignment]
    ece: bool = flag_property("ece", 13, 0b01000000)  # type: ignore[assignment]

    urg: bool = flag_property("syn", 13, 0b00100000)  # type: ignore[assignment]
    ack: bool = flag_property("ack", 13, 0b00010000)  # type: ignore[assignment]
    psh: bool = flag_property("psh", 13, 0b00001000)  # type: ignore[assignment]
    rst: bool = flag_property("rst", 13, 0b00000100)  # type: ignore[assignment]
    syn: bool = flag_property("syn", 13, 0b00000010)  # type: ignore[assignment]
    fin: bool = flag_property("fin", 13, 0b00000001)  # type: ignore[assignment]

    @property
    def header_len(self) -> int:
        """
        The TCP header length.
        """
        return self.data_offset * 4

    seq_num: int = raw_property("!I", 4, docs="The sequence number field.")  # type: ignore[assignment]
    ack_num: int = raw_property("!I", 8, docs="The acknowledgement number field.")  # type: ignore[assignment]

    window_size: int = raw_property("!H", 14, docs="The size of the receive window in bytes.")  # type: ignore[assignment]
    cksum: int = raw_property("!H", 16, docs="The TCP header checksum field.")  # type: ignore[assignment]
    urg_ptr: int = raw_property("!H", 18, docs="The Urgent Pointer field.")  # type: ignore[assignment]

    @property
    def data_offset(self) -> int:
        """
        The size of TCP header in 32bit words.
        """
        return self.raw[12] >> 4

    @data_offset.setter
    def data_offset(self, val: int) -> None:
        if val < 5 or val > 15:
            raise ValueError("TCP data offset must be greater or equal than 5 and less than 15.")
        struct.pack_into("!B", self.raw, 12, (val << 4) | (self.reserved << 1) | self.ns)

    @property
    def reserved(self) -> int:
        """
        The reserved field.
        """
        return (self.raw[12] >> 1) & 0x07

    @reserved.setter
    def reserved(self, val: int) -> None:
        struct.pack_into("!B", self.raw, 12, (self.data_offset << 4) | (val << 1) | self.ns)

    @property
    def control_bits(self) -> int:
        """
        The Control Bits field.
        """
        return struct.unpack_from("!H", self.raw, 12)[0] & 0x01FF

    @control_bits.setter
    def control_bits(self, val: int) -> None:
        struct.pack_into("!H", self.raw, 12, (self.data_offset << 12) | (self.reserved << 9) | (val & 0x01FF))
