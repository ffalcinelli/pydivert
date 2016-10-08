# -*- coding: utf-8 -*-
# Copyright (C) 2016  Fabio Falcinelli
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
from enum import Enum

__author__ = 'fabio'


# Divert layers.
class Layer(Enum):
    NETWORK = 0
    NETWORK_FORWARD = 1


# Divert Flag.
class Flag(Enum):
    SNIFF = 1
    DROP = 2


# Divert parameters.
class Param(Enum):
    QUEUE_LEN = 0  # Packet queue length 1 <default 512 < 8192
    QUEUE_TIME = 1  # Packet queue time 128 < default 512 < 2048


# Direction outbound/inbound
class Direction(Enum):
    OUTBOUND = 0
    INBOUND = 1


# Checksums
class CalcChecksumsOption(Enum):
    NO_IP_CHECKSUM = 1
    NO_ICMP_CHECKSUM = 2
    NO_ICMPV6_CHECKSUM = 4
    NO_TCP_CHECKSUM = 8
    NO_UDP_CHECKSUM = 16
