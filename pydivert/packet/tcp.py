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
from pydivert.util import indexbyte as i, flag_property


class TCPHeader(Header, PayloadMixin, PortMixin):
    urg = flag_property("syn", 13, 0b100000)
    ack = flag_property("ack", 13, 0b010000)
    psh = flag_property("psh", 13, 0b001000)
    rst = flag_property("rst", 13, 0b000100)
    syn = flag_property("syn", 13, 0b000010)
    fin = flag_property("fin", 13, 0b000001)

    @property
    def header_len(self):
        """
        The TCP header length.
        """
        return (i(self.raw[12]) >> 4) * 4
