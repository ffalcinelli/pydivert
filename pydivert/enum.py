# -*- coding: utf-8 -*-
# Copyright (C) 2013  Fabio Falcinelli
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
__author__ = 'fabio'


def enum(**enums):
    return type('Enum', (), enums)

#Divert layers.
Layer = enum(NETWORK=0, NETWORK_FORWARD=1)

#Divert Flag.
Flag = enum(SNIFF=1, DROP=2)

#Divert parameters.
Param = enum(QUEUE_LEN=0,  # Packet queue length 1<default 512 <8192
             QUEUE_TIME=1,  # Packet queue time 128 < default 512 < 2048
             MAX=1)

#Direction outbound/inbound
Direction = enum(OUTBOUND=0, INBOUND=1)

#Checksums
HelperOption = enum(NO_IP_CHECKSUM=1,
                    NO_ICMP_CHECKSUM=2,
                    NO_ICMPV6_CHECKSUM=4,
                    NO_TCP_CHECKSUM=8,
                    NO_UDP_CHECKSUM=16)

RegKeys = enum(VERSION10=r"SYSTEM\CurrentControlSet\Services\WinDivert1.0",
               VERSION11=r"SYSTEM\CurrentControlSet\Services\WinDivert1.1")