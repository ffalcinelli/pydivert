# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of either:
#
# 1) The GNU Lesser General Public License as published by the Free
#    Software Foundation, either version 3 of the License, or (at your
#    option) any later version.
#
# 2) The GNU General Public License as published by the Free Software
#    Foundation, either version 2 of the License, or (at your option)
#    any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License and the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# and the GNU General Public License along with this program.  If not,
# see <http://www.gnu.org/licenses/>.

"""
pydivert bundles the WinDivert binaries from
https://reqrypt.org/download/WinDivert-2.2.2-A.zip
"""

import functools
import os
import platform
import sys

try:
    from ctypes import (
        ARRAY,
        POINTER,
        GetLastError,
        WinDLL,
        WinError,
        c_char_p,
        c_int,
        c_int16,
        c_uint,
        c_uint8,
        c_uint32,
        c_uint64,
        c_void_p,
        windll,
    )
    from ctypes.wintypes import HANDLE
except (ImportError, AttributeError):
    # Fallback for non-Windows platforms (e.g. for running unit tests with mocks)
    from ctypes import ARRAY, POINTER, c_char_p, c_int, c_int16, c_uint, c_uint8, c_uint32, c_uint64, c_void_p

    def GetLastError():
        return 0

    WinError = OSError
    WinDLL = object
    windll = None
    HANDLE = c_void_p

from .structs import Overlapped, WinDivertAddress

ERROR_IO_PENDING = 997

here = os.path.abspath(os.path.dirname(__file__))

if platform.architecture()[0] != "64bit":
    raise RuntimeError("PyDivert only supports 64-bit architecture.")

DLL_PATH = os.path.join(here, "WinDivert64.dll")


def raise_on_error(f):
    """
    This decorator throws a WinError whenever GetLastError() returns an error.
    As as special case, ERROR_IO_PENDING is ignored.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        result = f(*args, **kwargs)

        # Determine if the function call failed.
        # WinDivertOpen returns INVALID_HANDLE_VALUE on failure.
        # All other functions return BOOL (False on failure).
        if f.__name__ == "WinDivertOpen":
            # INVALID_HANDLE_VALUE is -1 (or 0xFFFFFFFFFFFFFFFF for 64-bit void_p)
            failed = result == -1 or result == 0xFFFFFFFFFFFFFFFF or result is None
        else:
            failed = not result

        if failed:
            retcode = GetLastError()
            if retcode and retcode != ERROR_IO_PENDING:
                err = WinError(code=retcode)
                windll.kernel32.SetLastError(0)  # clear error code so that we don't raise twice.
                raise err
        return result

    return wrapper


WINDIVERT_FUNCTIONS = {
    "WinDivertHelperParsePacket": (
        [
            c_void_p,
            c_uint,
            c_void_p,
            c_void_p,
            c_void_p,
            c_void_p,
            c_void_p,
            c_void_p,
            c_void_p,
            c_void_p,
            POINTER(c_uint),
            c_void_p,
            POINTER(c_uint),
        ],
        c_int,
    ),
    "WinDivertHelperParseIPv4Address": ([c_char_p, POINTER(c_uint32)], c_int),
    "WinDivertHelperParseIPv6Address": ([c_char_p, POINTER(ARRAY(c_uint8, 16))], c_int),
    "WinDivertHelperCalcChecksums": ([c_void_p, c_uint, c_void_p, c_uint64], c_int),
    "WinDivertHelperCompileFilter": ([c_char_p, c_int, c_char_p, c_uint, POINTER(c_char_p), POINTER(c_uint)], c_int),
    "WinDivertHelperEvalFilter": ([c_char_p, c_void_p, c_uint, c_void_p], c_int),
    "WinDivertOpen": ([c_char_p, c_int, c_int16, c_uint64], HANDLE),
    "WinDivertRecv": ([HANDLE, c_void_p, c_uint, POINTER(c_uint), POINTER(WinDivertAddress)], c_int),
    "WinDivertSend": ([HANDLE, c_void_p, c_uint, POINTER(c_uint), POINTER(WinDivertAddress)], c_int),
    "WinDivertRecvEx": (
        [
            HANDLE,
            c_void_p,
            c_uint,
            POINTER(c_uint),
            c_uint64,
            POINTER(WinDivertAddress),
            POINTER(c_uint),
            POINTER(Overlapped),
        ],
        c_int,
    ),
    "WinDivertSendEx": (
        [HANDLE, c_void_p, c_uint, POINTER(c_uint), c_uint64, POINTER(WinDivertAddress), c_uint, POINTER(Overlapped)],
        c_int,
    ),
    "WinDivertShutdown": ([HANDLE, c_int], c_int),
    "WinDivertClose": ([HANDLE], c_int),
    "WinDivertGetParam": ([HANDLE, c_int, POINTER(c_uint64)], c_int),
    "WinDivertSetParam": ([HANDLE, c_int, c_uint64], c_int),
}

_instance = None


def instance():
    global _instance
    if _instance is None:
        _instance = WinDLL(DLL_PATH)
        for funcname, (argtypes, restype) in WINDIVERT_FUNCTIONS.items():
            func = getattr(_instance, funcname)
            func.argtypes = argtypes
            func.restype = restype
    return _instance


# Dark magic happens below.
# On init, windivert_dll.WinDivertOpen is a proxy function that loads the DLL on the first invocation
# and then replaces all existing proxy function with direct handles to the DLL's functions.


_module = sys.modules[__name__]


def _init():
    """
    Lazy-load DLL, replace proxy functions with actual ones.
    """
    i = instance()
    for funcname in WINDIVERT_FUNCTIONS:
        func = getattr(i, funcname)
        func = raise_on_error(func)
        setattr(_module, funcname, func)


def _mkprox(funcname):
    """
    Make lazy-init proxy function.
    """

    def prox(*args, **kwargs):
        _init()
        return getattr(_module, funcname)(*args, **kwargs)

    return prox


for funcname in WINDIVERT_FUNCTIONS:
    setattr(_module, funcname, _mkprox(funcname))
