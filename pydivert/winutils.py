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

import logging
import socket
import struct
import sys
from ctypes import Structure, Union, windll, POINTER
from ctypes import c_void_p, c_char_p
from ctypes.wintypes import DWORD, ULONG, HANDLE, BOOL

if sys.version_info < (3, 4):
    import win_inet_pton

    assert win_inet_pton


__author__ = 'fabio'
logger = logging.getLogger(__name__)


def string_to_addr(address_family, value):
    """
    Convert a ip string in dotted form into a packed, binary format
    """
    if address_family == socket.AF_INET:
        return struct.unpack("<I", socket.inet_pton(socket.AF_INET, value))[0]
    elif address_family == socket.AF_INET6:
        return struct.unpack("<IIII", socket.inet_pton(socket.AF_INET6, value))
    else:
        raise ValueError("Unknown address_family: %s" % address_family)


def addr_to_string(address_family, value):
    """
    Convert a packed, binary format into a ip string in dotted form
    """
    if address_family == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", value))
    elif address_family == socket.AF_INET6:
        return socket.inet_ntop(socket.AF_INET6, struct.pack("<IIII", *value))
    else:
        raise ValueError("Unknown address_family: %s" % address_family)


class _US(Structure):
    _fields_ = [
        ("Offset", DWORD),
        ("OffsetHigh", DWORD),
    ]


class _U(Union):
    _fields_ = [
        ("s", _US),
        ("Pointer", c_void_p),
    ]

    _anonymous_ = ("s",)


class OVERLAPPED(Structure):
    _fields_ = [
        ("Internal", POINTER(ULONG)),
        ("InternalHigh", POINTER(ULONG)),
        ("u", _U),
        ("hEvent", HANDLE),
    ]

    _anonymous_ = ("u",)


GetOverlappedResult = windll.kernel32.GetOverlappedResult
GetOverlappedResult.restype = BOOL
GetOverlappedResult.argtypes = [
    HANDLE, POINTER(OVERLAPPED), POINTER(DWORD), BOOL]

CreateEvent = windll.kernel32.CreateEventA
CreateEvent.restype = HANDLE
CreateEvent.argtypes = [c_void_p, BOOL, BOOL, c_char_p]
