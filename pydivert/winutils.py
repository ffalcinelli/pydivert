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
#
# Original credits for the convertion functions pton e ntop to
# https://gist.github.com/nnemkin/4966028
# Native inet_pton and inet_ntop implementation for Python on Windows (with ctypes).
from _ctypes import sizeof, FormatError, byref, POINTER
from ctypes import Structure, Union, c_short, c_byte, c_ushort, c_ulong, windll, c_int, string_at, create_string_buffer, \
    memmove, c_void_p, c_char_p
from ctypes.wintypes import DWORD, ULONG, HANDLE, BOOL
import logging
import socket
import struct
#_winreg has been renamed in python3 to winreg
import errno
from pydivert.exception import DriverNotRegisteredException

try:
    import winreg
except ImportError:
    import _winreg as winreg

__author__ = 'fabio'
logger = logging.getLogger(__name__)


def string_to_addr(address_family, value, encoding="UTF-8"):
    """
    Convert a ip string in dotted form into a packed, binary format
    """
    if address_family == socket.AF_INET:
        return struct.unpack("<I", inet_pton(socket.AF_INET, value, encoding))[0]
    elif address_family == socket.AF_INET6:
        return struct.unpack("<IIII", inet_pton(socket.AF_INET6, value, encoding))
    else:
        raise ValueError("Unknown address_family: %s" % address_family)


def addr_to_string(address_family, value, encoding="UTF-8"):
    """
    Convert a packed, binary format into a ip string in dotted form
    """
    if address_family == socket.AF_INET:
        return inet_ntop(socket.AF_INET, struct.pack("<I", value), encoding)
    elif address_family == socket.AF_INET6:
        return inet_ntop(socket.AF_INET6, struct.pack("<IIII", *value), encoding)
    else:
        raise ValueError("Unknown address_family: %s" % address_family)


class sockaddr(Structure):
    _fields_ = [("sa_family", c_short),
                ("__pad1", c_ushort),
                ("ipv4_addr", c_byte * 4),
                ("ipv6_addr", c_byte * 16),
                ("__pad2", c_ulong)]


WSAStringToAddressA = windll.ws2_32.WSAStringToAddressA
WSAAddressToStringA = windll.ws2_32.WSAAddressToStringA


def inet_pton(address_family, ip_string, encoding="UTF-8"):
    addr = sockaddr()
    addr.sa_family = address_family
    addr_size = c_int(sizeof(addr))

    if WSAStringToAddressA(ip_string.encode(encoding),
                           address_family,
                           None,
                           byref(addr),
                           byref(addr_size)) != 0:
        raise socket.error(FormatError())

    if address_family == socket.AF_INET:
        return string_at(addr.ipv4_addr, 4)
    if address_family == socket.AF_INET6:
        return string_at(addr.ipv6_addr, 16)

    raise socket.error('unknown address family')


def inet_ntop(address_family, packed_ip, encoding="UTF-8"):
    addr = sockaddr()
    addr.sa_family = address_family
    addr_size = c_int(sizeof(addr))
    ip_string = create_string_buffer(128)
    ip_string_size = c_int(sizeof(addr))

    if address_family == socket.AF_INET:
        if len(packed_ip) != sizeof(addr.ipv4_addr):
            raise socket.error('packed IP wrong length for inet_ntop')
        memmove(addr.ipv4_addr, packed_ip, 4)
    elif address_family == socket.AF_INET6:
        if len(packed_ip) != sizeof(addr.ipv6_addr):
            raise socket.error('packed IP wrong length for inet_ntop')
        memmove(addr.ipv6_addr, packed_ip, 16)
    else:
        raise socket.error('unknown address family')

    if WSAAddressToStringA(byref(addr),
                           addr_size,
                           None,
                           ip_string,
                           byref(ip_string_size)) != 0:
        raise socket.error(FormatError())

    return (ip_string[:ip_string_size.value - 1]).decode(encoding)


def print_services():
    k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
    count = 0
    while True:
        values = winreg.EnumKey(k, count)
        if values.startswith("Win"):
            print(values)
        count += 1
    winreg.CloseKey(k)


def get_reg_values(key, root_key=winreg.HKEY_LOCAL_MACHINE):
    """
    Given a key name, return a dictionary of its values.
    """
    count = 0
    result = {}
    try:
        #print_services()
        logger.debug("Reading key %s" % key)
        key_handle = winreg.OpenKey(root_key, key)
    except WindowsError as error:
        raise DriverNotRegisteredException()
    try:
        while True:
            values = winreg.EnumValue(key_handle, count)
            logger.debug("Found %s" % str(values))
            count += 1
            result.update({values[0]: values[1]})
    except WindowsError as error:
        if error.errno == errno.EINVAL:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Returning %d values" % len(result))
            return result
        else:
            logger.error(error)
            raise error
    finally:
        if key_handle:
            logger.debug("Closing key handle for key %s" % key)
            key_handle.Close()


def del_reg_key(sub_key, key, root_key=winreg.HKEY_LOCAL_MACHINE):
    """
    Given a key name, removes it from the Windows registry
    """
    logger.debug("Removing key %s" % key)
    try:
        key_handle = winreg.OpenKey(root_key, sub_key, 0, winreg.KEY_ALL_ACCESS)
        winreg.DeleteValue(key_handle, key)
    except WindowsError as e:
        if e.errno != errno.ENOENT:
            logger.error("Got error while deleting key %s: %s" % (key, e))
    else:
        logger.debug("Closing key handle for key %s" % key)
        key_handle.Close()


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


CloseHandle = windll.kernel32.CloseHandle
CloseHandle.restype = BOOL
CloseHandle.argtypes = [HANDLE]

GetLastError = windll.kernel32.GetLastError
GetLastError.restype = DWORD
GetLastError.argtypes = []

GetOverlappedResult = windll.kernel32.GetOverlappedResult
GetOverlappedResult.restype = BOOL
GetOverlappedResult.argtypes = [
    HANDLE, POINTER(OVERLAPPED), POINTER(DWORD), BOOL]

CreateEvent = windll.kernel32.CreateEventA
CreateEvent.restype = HANDLE
CreateEvent.argtypes = [c_void_p, BOOL, BOOL, c_char_p]