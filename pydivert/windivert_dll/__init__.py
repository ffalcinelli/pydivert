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
import sys
from ctypes.wintypes import HANDLE
from typing import TYPE_CHECKING, Any

from .structs import Overlapped as Overlapped
from .structs import WinDivertAddress as WinDivertAddress

# We use Any for windll and WinDLL to satisfy the type checker when accessing dynamic attributes
windll: Any
WinDLL: Any

if TYPE_CHECKING:
    # Define function signatures for type checking
    def WinDivertHelperParsePacket(
        pPacket: Any,
        packetLen: int,
        pIPv4Header: Any,
        pIPv6Header: Any,
        pICMPHeader: Any,
        pICMPv6Header: Any,
        pTCPHeader: Any,
        pUDPHeader: Any,
        pData: Any,
        pDataLen: Any,
        pNextHeader: Any,
        pNextHeaderLen: Any,
        pFlags: Any,
    ) -> int: ...

    def WinDivertHelperParseIPv4Address(addrStr: bytes, pAddr: Any) -> int: ...
    def WinDivertHelperParseIPv6Address(addrStr: bytes, pAddr: Any) -> int: ...
    def WinDivertHelperCalcChecksums(pPacket: Any, packetLen: int, pAddr: Any, flags: int) -> int: ...
    def WinDivertHelperCompileFilter(
        filter: bytes, layer: int, errorStr: Any, errorPos: Any, pMsg: Any, pPos: Any
    ) -> int: ...
    def WinDivertHelperEvalFilter(filter: bytes, pPacket: Any, packetLen: int, pAddr: Any) -> bool: ...
    def WinDivertOpen(filter: bytes, layer: int, priority: int, flags: int) -> HANDLE: ...
    def WinDivertRecv(pHandle: HANDLE, pPacket: Any, packetLen: int, pRecvLen: Any, pAddr: Any) -> int: ...
    def WinDivertSend(pHandle: HANDLE, pPacket: Any, packetLen: int, pSendLen: Any, pAddr: Any) -> int: ...
    def WinDivertRecvEx(
        pHandle: HANDLE,
        pPacket: Any,
        packetLen: int,
        pRecvLen: Any,
        flags: int,
        pAddr: Any,
        pAddrLen: Any,
        pOverlapped: Any,
    ) -> int: ...
    def WinDivertSendEx(
        pHandle: HANDLE,
        pPacket: Any,
        packetLen: int,
        pSendLen: Any,
        flags: int,
        pAddr: Any,
        addrLen: int,
        pOverlapped: Any,
    ) -> int: ...
    def WinDivertShutdown(pHandle: HANDLE, how: int) -> int: ...
    def WinDivertClose(pHandle: HANDLE) -> int: ...
    def WinDivertGetParam(pHandle: HANDLE, param: int, pValue: Any) -> int: ...
    def WinDivertSetParam(pHandle: HANDLE, param: int, value: int) -> int: ...

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
    )
    from ctypes import (
        WinDLL as _WinDLL,
    )
    from ctypes import (
        windll as _windll,
    )
    windll = _windll
    WinDLL = _WinDLL

    # kernel32 functions
    def CreateEventW(*args, **kwargs):
        f = windll.kernel32.CreateEventW
        f.argtypes = [c_void_p, c_int, c_int, c_void_p]
        f.restype = HANDLE
        return f(*args, **kwargs)

    def CloseHandle(handle):
        f = windll.kernel32.CloseHandle
        f.argtypes = [HANDLE]
        f.restype = c_int
        return f(handle)

    def WaitForSingleObject(handle, timeout):
        f = windll.kernel32.WaitForSingleObject
        f.argtypes = [HANDLE, c_uint]
        f.restype = c_uint
        return f(handle, timeout)

    def GetLastError():
        f = windll.kernel32.GetLastError
        f.argtypes = []
        f.restype = c_uint
        return f()

    def SetLastError(dwErrCode):
        if windll:
            f = windll.kernel32.SetLastError
            f.argtypes = [c_uint]
            f.restype = None
            return f(dwErrCode)
        return None

    def WinError(code=None, desc=None):
        return ctypes.WinError(code, desc)

except (ImportError, AttributeError):  # pragma: no cover
    # Fallback for non-Windows platforms (e.g. for running unit tests with mocks)
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
    )
    windll = None
    WinDLL = ctypes.cdll.LoadLibrary if hasattr(ctypes.cdll, "LoadLibrary") else None

    def GetLastError():
        if windll:
            return windll.kernel32.GetLastError()
        return 0

    def CreateEventW(*args, **kwargs):
        if windll:
            return windll.kernel32.CreateEventW(*args, **kwargs)
        return 0

    def CloseHandle(handle):
        if windll:
            return windll.kernel32.CloseHandle(handle)
        return True

    def WaitForSingleObject(handle, timeout):
        if windll:
            return windll.kernel32.WaitForSingleObject(handle, timeout)
        return 0

    def SetLastError(dwErrCode):
        if windll:
            return windll.kernel32.SetLastError(dwErrCode)
        return None

    def WinError(code=None, desc=None):
        err = OSError(code, desc)
        if code is not None:
            err.winerror = code
        return err

ERROR_IO_PENDING = 997
INFINITE = 0xFFFFFFFF


def raise_on_error(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        res = f(*args, **kwargs)

        if f.__name__ == "WinDivertOpen":
            # INVALID_HANDLE_VALUE is -1 (or 0xFFFFFFFFFFFFFFFF for 64-bit void_p)
            failed = res == -1 or res == 0xFFFFFFFFFFFFFFFF or res is None
        elif f.__name__.startswith("WinDivertHelper"):
            # WinDivertHelper functions generally return 0/NULL on failure,
            # but for EvalFilter it returns 0 (False) as a valid result.
            # Most helpers don't need automated WinError raising.
            return res
        else:
            failed = not res

        if failed:
            retcode = GetLastError()
            if retcode and retcode != ERROR_IO_PENDING:
                err = WinError(code=retcode)
                try:
                    SetLastError(0)
                except Exception:
                    pass
                raise err
        return res

    return wrapper


DLL_PATH = os.path.join(os.path.dirname(__file__), "WinDivert64.dll")

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
    "WinDivertOpen": ([c_char_p, c_int, c_int16, c_uint64], HANDLE),
    "WinDivertRecv": ([HANDLE, c_void_p, c_uint, POINTER(c_uint), c_void_p], c_int),
    "WinDivertRecvEx": (
        [HANDLE, c_void_p, c_uint, POINTER(c_uint), c_uint64, c_void_p, POINTER(c_uint), c_void_p],
        c_int,
    ),
    "WinDivertSend": ([HANDLE, c_void_p, c_uint, POINTER(c_uint), c_void_p], c_int),
    "WinDivertSendEx": (
        [HANDLE, c_void_p, c_uint, POINTER(c_uint), c_uint64, c_void_p, c_uint, c_void_p],
        c_int,
    ),
    "WinDivertHelperCalcChecksums": ([c_void_p, c_uint, c_void_p, c_uint64], c_uint),
    "WinDivertHelperEvalFilter": ([c_char_p, c_void_p, c_uint, c_void_p], c_int),
    "WinDivertHelperCompileFilter": (
        [c_char_p, c_int, c_char_p, c_uint, POINTER(c_char_p), POINTER(c_uint)],
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


def __getattr__(name: str) -> Any:
    """
    Handle dynamic access for WinDivert DLL functions.
    This helps type checkers like Pyright (ty) understand that this module
    dynamically provides attributes not explicitly defined.
    """
    if name in WINDIVERT_FUNCTIONS:
        return _mkprox(name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


for funcname in WINDIVERT_FUNCTIONS:
    setattr(_module, funcname, _mkprox(funcname))
