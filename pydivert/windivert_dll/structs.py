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
import ctypes


class WinDivertAddress(ctypes.Structure):
    """
    Ctypes Structure for WINDIVERT_ADDRESS.
    The WINDIVERT_ADDRESS structure represents the "address" of a captured or injected packet.
    The address includes the packet's network interfaces and the packet direction.


    typedef struct
    {
        INT64  Timestamp;
        UINT32 IfIdx;
        UINT32 SubIfIdx;
        UINT8  Direction:1;
        UINT8  Loopback:1;
        UINT8  Impostor:1;
        UINT8  PseudoIPChecksum:1;
        UINT8  PseudoTCPChecksum:1;
        UINT8  PseudoUDPChecksum:1;
    } WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;

    Fields:

        - Timestamp: A timestamp indicating when WinDivert first captured the packet.
        - IfIdx: The interface index on which the packet arrived (for inbound packets), or is to be sent (for outbound packets).
        - SubIfIdx: The sub-interface index for IfIdx.
        - Direction: The packet's direction. The possible values are
            - WINDIVERT_DIRECTION_OUTBOUND with value 0 for outbound packets.
            - WINDIVERT_DIRECTION_INBOUND with value 1 for inbound packets.
        - Loopback: Set to 1 for loopback packets, 0 otherwise
        - Impostor: Set to 1 for impostor packets, 0 otherwise.
        - PseudoIPChecksum: Set to 1 for packets with a pseudo IPv4 checksum, 0 otherwise.
        - PseudoTCPChecksum: Set to 1 for packets with a pseudo TCP checksum, 0 otherwise.
        - PseudoTCPChecksum: Set to 1 for packets with a pseudo UDP checksum, 0 otherwise.
    """
    _fields_ = [
        ("Timestamp", ctypes.c_int64),
        ("IfIdx", ctypes.c_uint32),
        ("SubIfIdx", ctypes.c_uint32),
        ("Direction", ctypes.c_uint8),
        ("Loopback", ctypes.c_uint8),
        ("Impostor", ctypes.c_uint8),
        ("PseudoIPChecksum", ctypes.c_uint8),
        ("PseudoTCPChecksum", ctypes.c_uint8),
        ("PseudoUDPChecksum", ctypes.c_uint8),
    ]
