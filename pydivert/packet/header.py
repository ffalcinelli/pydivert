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
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from pydivert.packet import Packet


class Header:
    __slots__ = ("_packet", "_start")
    __repr_fields__: tuple[str, ...] = ()

    def __init__(self, packet: Packet, start: int = 0) -> None:
        self._packet = packet
        self._start = start

    def __repr__(self) -> str:
        fields = []
        for k in self.__repr_fields__:
            try:
                v = getattr(self, k)
                if v is None:
                    continue
                if k == "raw" and isinstance(v, memoryview):
                    v = f"<memoryview of {len(v)} bytes>"
                fields.append(f"{k}={v!r}")
            except (AttributeError, ValueError):
                continue
        return f"{self.__class__.__name__}({', '.join(fields)})"

    @property
    def raw(self) -> memoryview:
        """
        The raw header, possibly including payload.
        """
        return self._packet.raw[self._start :]

    @raw.setter
    def raw(self, val: bytes | bytearray | memoryview) -> None:
        if len(val) == len(self.raw):
            self.raw[:] = val
        else:
            self._packet.raw = memoryview(bytearray(self._packet.raw[: self._start].tobytes() + val))
            if self._packet.ip:
                self._packet.ip.packet_len = len(self._packet.raw)


class RawProtocol:
    __slots__ = ()

    @property
    def raw(self) -> memoryview:
        raise NotImplementedError()

    @raw.setter
    def raw(self, val: bytes | bytearray | memoryview) -> None:
        raise NotImplementedError()


class PayloadMixin(RawProtocol):
    __slots__ = ()

    @property
    def header_len(self) -> int:
        raise NotImplementedError()  # pragma: no cover

    @property
    def payload(self) -> bytes:
        """
        The packet payload data.
        """
        return self.raw[self.header_len :].tobytes()

    @payload.setter
    def payload(self, val: bytes | bytearray | memoryview) -> None:
        if not isinstance(val, (bytes, bytearray, memoryview)):
            raise AttributeError("payload must be bytes-like")
        if len(val) == len(self.raw) - self.header_len:
            self.raw[self.header_len :] = val
        else:
            self.raw = self.raw[: self.header_len].tobytes() + val


class PortMixin(RawProtocol):
    __slots__ = ()

    @property
    def src_port(self) -> int:
        """
        The source port.
        """
        return struct.unpack_from("!H", self.raw, 0)[0]

    @src_port.setter
    def src_port(self, val: int) -> None:
        self.raw[0:2] = struct.pack("!H", val)

    @property
    def dst_port(self) -> int:
        """
        The destination port.
        """
        return struct.unpack_from("!H", self.raw, 2)[0]

    @dst_port.setter
    def dst_port(self, val: int) -> None:
        self.raw[2:4] = struct.pack("!H", val)
