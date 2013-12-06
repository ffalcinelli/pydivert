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
import logging
import socket
import ctypes
import struct
#_winreg has been renamed in python3 to winreg
import errno

try:
    import winreg
except ImportError:
    import _winreg as winreg

__author__ = 'fabio'
logger = logging.getLogger(__name__)


def string_to_addr(address_family, value):
    """
    Convert a ip string in dotted form into a packed, binary format
    """
    if address_family == socket.AF_INET:
        return struct.unpack("<I", inet_pton(socket.AF_INET, value))[0]
    elif address_family == socket.AF_INET6:
        return struct.unpack("<IIII", inet_pton(socket.AF_INET6, value))
    else:
        raise ValueError("Unknown address_family: %s" % address_family)


def addr_to_string(address_family, value):
    """
    Convert a packed, binary format into a ip string in dotted form
    """
    if address_family == socket.AF_INET:
        return inet_ntop(socket.AF_INET, struct.pack("<I", value))
    elif address_family == socket.AF_INET6:
        return inet_ntop(socket.AF_INET6, struct.pack("<IIII", *value))
    else:
        raise ValueError("Unknown address_family: %s" % address_family)


class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_short),
                ("__pad1", ctypes.c_ushort),
                ("ipv4_addr", ctypes.c_byte * 4),
                ("ipv6_addr", ctypes.c_byte * 16),
                ("__pad2", ctypes.c_ulong)]


WSAStringToAddressA = ctypes.windll.ws2_32.WSAStringToAddressA
WSAAddressToStringA = ctypes.windll.ws2_32.WSAAddressToStringA


def inet_pton(address_family, ip_string):
    addr = sockaddr()
    addr.sa_family = address_family
    addr_size = ctypes.c_int(ctypes.sizeof(addr))

    if WSAStringToAddressA(ip_string.encode("UTF-8"),
                           address_family,
                           None,
                           ctypes.byref(addr),
                           ctypes.byref(addr_size)) != 0:
        raise socket.error(ctypes.FormatError())

    if address_family == socket.AF_INET:
        return ctypes.string_at(addr.ipv4_addr, 4)
    if address_family == socket.AF_INET6:
        return ctypes.string_at(addr.ipv6_addr, 16)

    raise socket.error('unknown address family')


def inet_ntop(address_family, packed_ip):
    addr = sockaddr()
    addr.sa_family = address_family
    addr_size = ctypes.c_int(ctypes.sizeof(addr))
    ip_string = ctypes.create_string_buffer(128)
    ip_string_size = ctypes.c_int(ctypes.sizeof(addr))

    if address_family == socket.AF_INET:
        if len(packed_ip) != ctypes.sizeof(addr.ipv4_addr):
            raise socket.error('packed IP wrong length for inet_ntop')
        ctypes.memmove(addr.ipv4_addr, packed_ip, 4)
    elif address_family == socket.AF_INET6:
        if len(packed_ip) != ctypes.sizeof(addr.ipv6_addr):
            raise socket.error('packed IP wrong length for inet_ntop')
        ctypes.memmove(addr.ipv6_addr, packed_ip, 16)
    else:
        raise socket.error('unknown address family')

    if WSAAddressToStringA(ctypes.byref(addr),
                           addr_size,
                           None,
                           ip_string,
                           ctypes.byref(ip_string_size)) != 0:
        raise socket.error(ctypes.FormatError())

    return (ip_string[:ip_string_size.value - 1]).decode("UTF-8")


def get_reg_values(key, root_key=winreg.HKEY_LOCAL_MACHINE):
    """
    Given a key name, return a dictionary of its values.
    """
    key_handle = None
    count = 0
    result = {}
    try:
        logger.debug("Reading key %s" % key)
        key_handle = winreg.OpenKey(root_key, key)
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
    key_handle = None
    try:
        logger.debug("Removing key %s" % key)
        key_handle = winreg.OpenKey(root_key, sub_key, 0, winreg.KEY_ALL_ACCESS)
        winreg.DeleteValue(key_handle, key)
        #winreg.CloseKey(key_handle)
    except WindowsError as e:
        logger.error("Got error while deleting key %s: %s" % (key, e))
    finally:
        if key_handle:
            logger.debug("Closing key handle for key %s" % key)
            key_handle.Close()
