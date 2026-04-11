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
from pydivert.util import raw_property


class UDPHeader(Header, PayloadMixin, PortMixin):
    __slots__ = ()
    __match_args__ = ("src_port", "dst_port", "payload_len")
    __repr_fields__ = ("cksum", "dst_port", "header_len", "payload", "payload_len", "raw", "src_port")
    header_len: int = 8

    @property
    def payload(self) -> bytes:
        return PayloadMixin.payload.fget(self)  # type: ignore

    @payload.setter
    def payload(self, val: bytes | bytearray | memoryview) -> None:
        PayloadMixin.payload.fset(self, val)  # type: ignore
        self.payload_len = len(val)

    payload.__doc__ = PayloadMixin.payload.__doc__

    @property
    def payload_len(self) -> int:
        return struct.unpack_from("!H", self.raw, 4)[0] - 8

    @payload_len.setter
    def payload_len(self, val: int) -> None:
        self.raw[4:6] = struct.pack("!H", val + 8)

    @property
    def cksum(self) -> int:
        """
        The UDP header checksum field.
        """
        return struct.unpack_from("!H", self.raw, 6)[0]

    @cksum.setter
    def cksum(self, val: int) -> None:
        struct.pack_into("!H", self.raw, 6, val)
