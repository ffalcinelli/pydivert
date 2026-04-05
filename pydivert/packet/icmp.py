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

from pydivert.packet.header import Header, PayloadMixin
from pydivert.util import raw_property


class ICMPHeader(Header, PayloadMixin):
    __repr_fields__ = ("cksum", "code", "header_len", "payload", "raw", "type")

    @property
    def type(self) -> int:
        """
        The ICMP message type.
        """
        return self.raw[0]

    @type.setter
    def type(self, val: int) -> None:
        self.raw[0] = val

    @property
    def code(self) -> int:
        """
        The ICMP message code.
        """
        return self.raw[1]

    @code.setter
    def code(self, val: int) -> None:
        self.raw[1] = val

    cksum: int = raw_property("!H", 2, docs="The ICMP header checksum field.")  # type: ignore[assignment]


class ICMPv4Header(ICMPHeader):
    header_len: int = 4


class ICMPv6Header(ICMPHeader):
    header_len: int = 4
