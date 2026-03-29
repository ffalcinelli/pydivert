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
# see <http://www.gnu.org/licenses/>.

import struct
from typing import Any


class Header:
    def __init__(self, packet: Any, start: int = 0):
        self._packet = packet
        self._start = start

    @property
    def raw(self) -> Any:  # type: ignore[has-type]
        """
        The raw header, possibly including payload.
        """
        return self._packet.raw[self._start:]

    @raw.setter
    def raw(self, val):
        if len(val) == len(self.raw):
            self.raw[:] = val
        else:
            self._packet.raw = memoryview(bytearray(
                self._packet.raw[:self._start].tobytes() + val
            ))
            self._packet.ip.packet_len = len(self._packet.raw)


class PayloadMixin:
    @property
    def raw(self) -> Any:
        raise NotImplementedError()

    @property
    def header_len(self):
        raise NotImplementedError()  # pragma: no cover

    @property
    def payload(self):
        """
        The packet payload data.
        """
        return self.raw[self.header_len:].tobytes()

    @payload.setter
    def payload(self, val):
        if len(val) == len(self.raw) - self.header_len:
            self.raw[self.header_len:] = val
        else:
            self.raw = self.raw[:self.header_len].tobytes() + val


class PortMixin:
    @property
    def raw(self) -> Any:
        raise NotImplementedError()

    @property
    def src_port(self) -> Any:
        """
        The source port.
        """
        return struct.unpack_from("!H", self.raw, 0)[0]  # type: ignore[attr-defined]

    @property
    def dst_port(self) -> Any:
        """
        The destination port.
        """
        return struct.unpack_from("!H", self.raw, 2)[0]  # type: ignore[attr-defined]

    @src_port.setter  # type: ignore
    def src_port(self, val: Any):
        self.raw[0:2] = struct.pack("!H", val)

    @dst_port.setter  # type: ignore
    def dst_port(self, val: Any):
        self.raw[2:4] = struct.pack("!H", val)
