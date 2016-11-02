# -*- coding: utf-8 -*-
# Copyright (C) 2016  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from pydivert.packet.header import Header, PayloadMixin, PortMixin
from pydivert.util import indexbyte as i, PY2, PY34


def flagproperty(name, bit):
    @property
    def flag(self):
        return bool(i(self.raw[13]) & bit)

    @flag.setter
    def flag(self, val):
        flags = i(self.raw[13])
        if val:
            flags |= bit
        else:
            flags &= ~bit

        self.raw[13] = i(flags)

    if PY2 or PY34:
        pass  # .__doc__ is readonly on Python 2 and under 3.5.
    else:
        flag.__doc__ = """
            Indicates if the {} flag is set.
            """.format(name.upper())

    return flag


class TCPHeader(Header, PayloadMixin, PortMixin):
    urg = flagproperty("syn", 0b100000)
    ack = flagproperty("ack", 0b010000)
    psh = flagproperty("psh", 0b001000)
    rst = flagproperty("rst", 0b000100)
    syn = flagproperty("syn", 0b000010)
    fin = flagproperty("fin", 0b000001)

    @property
    def header_len(self):
        """
        The TCP header length.
        """
        return (i(self.raw[12]) >> 4) * 4
