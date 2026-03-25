# -*- coding: utf-8 -*-
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
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


from ctypes.wintypes import DWORD, HANDLE


class Overlapped(ctypes.Structure):
    """
    Ctypes Structure for OVERLAPPED.
    """
    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", DWORD),
        ("OffsetHigh", DWORD),
        ("hEvent", HANDLE),
    ]


class WinDivertAddress(ctypes.Structure):
    """
    Ctypes Structure for WINDIVERT_ADDRESS (WinDivert 2.2).
    """
    class _Union(ctypes.Union):
        class _Network(ctypes.Structure):
            _fields_ = [
                ("IfIdx", ctypes.c_uint32),
                ("SubIfIdx", ctypes.c_uint32),
            ]
        class _Flow(ctypes.Structure):
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
        class _Socket(ctypes.Structure):
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
        class _Reflect(ctypes.Structure):
            _fields_ = [
                ("Timestamp", ctypes.c_int64),
                ("ProcessId", ctypes.c_uint32),
                ("Layer", ctypes.c_uint32, 8),
                ("Reserved2", ctypes.c_uint32, 24),
            ]
        _fields_ = [
            ("Network", _Network),
            ("Flow", _Flow),
            ("Socket", _Socket),
            ("Reflect", _Reflect),
            ("Reserved3", ctypes.c_uint32 * 16),
        ]
    _anonymous_ = ("u",)
    _fields_ = [
        ("Timestamp", ctypes.c_int64),
        ("Layer", ctypes.c_uint32, 8),
        ("Event", ctypes.c_uint32, 8),
        ("Sniffed", ctypes.c_uint32, 1),
        ("Outbound", ctypes.c_uint32, 1),
        ("Loopback", ctypes.c_uint32, 1),
        ("Impostor", ctypes.c_uint32, 1),
        ("IPv4", ctypes.c_uint32, 1),
        ("IPv6", ctypes.c_uint32, 1),
        ("IPChecksum", ctypes.c_uint32, 1),
        ("TCPChecksum", ctypes.c_uint32, 1),
        ("UDPChecksum", ctypes.c_uint32, 1),
        ("Reserved1", ctypes.c_uint32, 7),
        ("u", _Union),
    ]
