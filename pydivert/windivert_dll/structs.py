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
import binascii
import ctypes
import struct
import socket
import psutil
import ipaddress

from .. import Layer


class Network(ctypes.Structure):
    _fields_ = [
        ("IfIdx", ctypes.c_uint32),
        ("SubIfIdx", ctypes.c_uint32),
    ]


class Flow(ctypes.Structure):
    _fields_ = [
        ("EndpointId", ctypes.c_uint64),
        ("ParentEndpointId", ctypes.c_uint64),
        ("ProcessId", ctypes.c_uint32),
        ("LocalAddr", ctypes.c_uint32 * 4),
        ("RemoteAddr", ctypes.c_uint32 * 4),

        ("LocalPort", ctypes.c_uint16),
        ("RemotePort", ctypes.c_uint16),
        ("Protocol", ctypes.c_uint8),
    ]


class Socket(ctypes.Structure):
    _fields_ = [
        ("EndpointId", ctypes.c_uint64),
        ("ParentEndpointId", ctypes.c_uint64),
        ("ProcessId", ctypes.c_uint32),
        ("LocalAddr", ctypes.c_uint32 * 4),
        ("RemoteAddr", ctypes.c_uint32 * 4),

        ("LocalPort", ctypes.c_uint16),
        ("RemotePort", ctypes.c_uint16),
        ("Protocol", ctypes.c_uint8),
    ]


class Reflect(ctypes.Structure):
    _fields_ = [

        ("TimestampR", ctypes.c_int64),
        ("ProcessId", ctypes.c_uint32),
        ("Layer", ctypes.c_uint64),
        ("Flags", ctypes.c_uint64),
        ("Priority", ctypes.c_int16),
    ]


class Reserved3(ctypes.Union):
    _fields_ = [
        ("Network", Network),
        ("Flow", Flow),
        ("Socket", Socket),
        ("Reflect", Reflect),

        ("Reserved3", ctypes.c_uint8 * 64),
    ]


class WinDivertAddress(ctypes.Structure):
    """
    Ctypes Structure for WINDIVERT_ADDRESS.
    The WINDIVERT_ADDRESS structure represents the "address" of a captured or injected packet.
    The address includes the packet's network interfaces and the packet direction.

    typedef struct
    {
        INT64  Timestamp;                   /* Packet's timestamp. */
        UINT32 Layer:8;                     /* Packet's layer. */
        UINT32 Event:8;                     /* Packet event. */
        UINT32 Sniffed:1;                   /* Packet was sniffed? */
        UINT32 Outbound:1;                  /* Packet is outound? */
        UINT32 Loopback:1;                  /* Packet is loopback? */
        UINT32 Impostor:1;                  /* Packet is impostor? */
        UINT32 IPv6:1;                      /* Packet is IPv6? */
        UINT32 IPChecksum:1;                /* Packet has valid IPv4 checksum? */
        UINT32 TCPChecksum:1;               /* Packet has valid TCP checksum? */
        UINT32 UDPChecksum:1;               /* Packet has valid UDP checksum? */
        UINT32 Reserved1:8;
        UINT32 Reserved2;
        union
        {
            WINDIVERT_DATA_NETWORK Network; /* Network layer data. */
            WINDIVERT_DATA_FLOW Flow;       /* Flow layer data. */
            WINDIVERT_DATA_SOCKET Socket;   /* Socket layer data. */
            WINDIVERT_DATA_REFLECT Reflect; /* Reflect layer data. */
            UINT8 Reserved3[64];
        };
    } WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;

    Fields:

        - IfIdx: The interface index on which the packet arrived (for inbound packets),
          or is to be sent (for outbound packets).
        - SubIfIdx: The sub-interface index for IfIdx.
        - Direction: The packet's direction. The possible values are
                    - WINDIVERT_DIRECTION_OUTBOUND with value 0 for outbound packets.
                    - WINDIVERT_DIRECTION_INBOUND with value 1 for inbound packets.
    """
    _fields_ = [
        ("Timestamp", ctypes.c_uint64),
        ("Layer", ctypes.c_uint32, 8),
        ("Event", ctypes.c_uint32, 8),
        ("Sniffed", ctypes.c_uint32, 1),
        ("Outbound", ctypes.c_uint32, 1),
        ("Loopback", ctypes.c_uint32, 1),
        ("Impostor", ctypes.c_uint32, 1),
        ("IPv6", ctypes.c_uint32, 1),
        ("IPChecksum", ctypes.c_uint32, 1),
        ("TCPChecksum", ctypes.c_uint32, 1),
        ("UDPChecksum", ctypes.c_uint32, 1),
        ("Reserved1", ctypes.c_uint32, 8),
        ("Reserved2", ctypes.c_uint32),
        ("Reserved3", Reserved3),
    ]

    def dict(self):
        d = {}
        for one in self._fields_:
            k = one[0]
            v = getattr(self, k)

            d[k] = v
        Reserved3 = {
            Layer.NETWORK: Network,
            Layer.FLOW: Flow,
            Layer.SOCKET: Socket,
            Layer.REFLECT: Reflect,
        }.get(self.Layer, None)
        if Reserved3:
            for one in Reserved3._fields_:
                t = Reserved3.__name__
                k = one[0]
                v = getattr(getattr(self.Reserved3, t), k)
                d[k] = v
                if k in ("LocalAddr", "RemoteAddr"):
                    # print(v[:])
                    if self.IPv6:
                        d[k] = binascii.b2a_hex(bytes(v))
                        d[k + "_"] = ipaddress.IPv6Address(int.from_bytes(bytes(v), "little"))
                    else:
                        d[k] = v[0]
                        d[k + "_"] = ipaddress.IPv4Address(v[0])
                if k in ("ProcessId"):
                    p = psutil.Process(v)
                    d["ProcessName"] = p.name()
                    d["ProcessPath"] = p.exe()
        d["Reserved3"] = binascii.b2a_hex(struct.pack("64s", bytes(self.Reserved3.Reserved3)))
        return d
