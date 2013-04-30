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


#TODO: is this worth?
#def enum(**enums):
#    return type('Enum', (), enums)
#
#Layers = enum(DIVERT_LAYER_NETWORK=0, DIVERT_LAYER_NETWORK_FORWARD=1)

#Divert layers.
DIVERT_LAYER_NETWORK = 0
DIVERT_LAYER_NETWORK_FORWARD = 1

#Divert Flags.
DIVERT_FLAG_SNIFF = 1
DIVERT_FLAG_DROP = 2

#Divert parameters.
DIVERT_PARAM_QUEUE_LEN = 0  # Packet queue length 1<default 512 <8192
DIVERT_PARAM_QUEUE_TIME = 1  # Packet queue time 32 < default 256 < 1024
DIVERT_PARAM_MAX = DIVERT_PARAM_QUEUE_TIME

#Direction outbound/inbound
DIVERT_DIRECTION_OUTBOUND = 0
DIVERT_DIRECTION_INBOUND = 1

#Checksums
DIVERT_HELPER_NO_IP_CHECKSUM = 1
DIVERT_HELPER_NO_ICMP_CHECKSUM = 2
DIVERT_HELPER_NO_ICMPV6_CHECKSUM = 4
DIVERT_HELPER_NO_TCP_CHECKSUM = 8
DIVERT_HELPER_NO_UDP_CHECKSUM = 16

