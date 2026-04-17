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
# see <https://www.gnu.org/licenses/>.

"""
pydivert bundles the WinDivert binaries from
https://reqrypt.org/download/WinDivert-2.2.2-A.zip
"""

import ctypes
import functools
import os
import platform
import sys
from typing import Any, cast

try:
    from ctypes import (
        POINTER,
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

    # kernel32 functions
    def CreateEventW(*args, **kwargs):
        f = cast(Any, windll).kernel32.CreateEventW
        f.argtypes = [c_void_p, c_int, c_int, c_void_p]
        f.restype = HANDLE
        return f(*args, **kwargs)

    def CloseHandle(handle):
        f = cast(Any, windll).kernel32.CloseHandle
        f.argtypes = [HANDLE]
        f.restype = c_int
        return f(handle)

    def WaitForSingleObject(handle, timeout):
        f = cast(Any, windll).kernel32.WaitForSingleObject
        f.argtypes = [HANDLE, c_uint]
        f.restype = c_uint
        return f(handle, timeout)

    def GetLastError():
        f = cast(Any, windll).kernel32.GetLastError
        f.argtypes = []
        f.restype = c_uint
        return f()

    def SetLastError(dwErrCode):
        if windll:
            f = cast(Any, windll).kernel32.SetLastError
            f.argtypes = [c_uint]
            f.restype = None
            return f(dwErrCode)
        return None

    def WinError(code=None, desc=None):
        return ctypes.WinError(code, desc)

    WinDLL: type[Any] = ctypes.WinDLL
except (ImportError, AttributeError):  # pragma: no cover
    # Fallback for non-Windows platforms (e.g. for running unit tests with mocks)
    from ctypes import POINTER, c_char_p, c_int, c_int16, c_uint, c_uint8, c_uint32, c_uint64, c_void_p

    def GetLastError():
        if windll:
            return cast(Any, windll).kernel32.GetLastError()
        return 0

    def CreateEventW(*args, **kwargs):
        if windll:
            return cast(Any, windll).kernel32.CreateEventW(*args, **kwargs)
        return 0

    def CloseHandle(handle):
        if windll:
            return cast(Any, windll).kernel32.CloseHandle(handle)
        return True

    def WaitForSingleObject(handle, timeout):
        if windll:
            return cast(Any, windll).kernel32.WaitForSingleObject(handle, timeout)
        return 0

    def SetLastError(dwErrCode):
        if windll:
            return cast(Any, windll).kernel32.SetLastError(dwErrCode)
        return None

    def WinError(code=None, desc=None):
        err = OSError(code, desc)
        if code is not None:
            err.winerror = code
        return err

    class WinDLL:
        def __init__(self, *args, **kwargs):
            pass

    windll: Any = None
    HANDLE = c_void_p

from .structs import Overlapped, WinDivertAddress

ERROR_IO_PENDING = 997
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0

here = os.path.abspath(os.path.dirname(__file__))

if platform.architecture()[0] != "64bit":  # pragma: no cover
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
                try:
                    SetLastError(0)  # clear error code so that we don't raise twice.
                except Exception:
                    pass
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
    "WinDivertHelperParseIPv6Address": ([c_char_p, POINTER(c_uint8 * 16)], c_int),
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


_module: Any = sys.modules[__name__]


def _init():
    """
    Initializes the WinDivert DLL.
    """
    try:
        dll = WinDLL(DLL_PATH)
    except Exception as e:  # pragma: no cover
        raise WinError(f"Failed to load {DLL_PATH}: {e}") from e

    for funcname, (argtypes, restype) in WINDIVERT_FUNCTIONS.items():
        f = getattr(dll, funcname)
        f.argtypes = argtypes
        f.restype = restype
        setattr(_module, funcname, raise_on_error(f))

    # Replace proxy functions with direct handles
    setattr(_module, "_init", lambda: None)  # noqa: B010


def _mkprox(funcname):
    """
    Create a proxy function that will initialize the DLL on the first call.
    windivert_dll.WinDivertOpen is a proxy function that loads the DLL on the first invocation
    and then replaces all existing proxy function with direct handles to the DLL's functions.
    """

    def prox(*args, **kwargs):
        _init()
        return getattr(_module, funcname)(*args, **kwargs)

    return prox


for funcname in WINDIVERT_FUNCTIONS:
    setattr(_module, funcname, _mkprox(funcname))
