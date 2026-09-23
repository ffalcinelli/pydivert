# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
"""
ctypes binding to libebpfdivert, the Linux counterpart of WinDivert.

libebpfdivert exposes a WinDivert-shaped C API (open/recv/send/params/
shutdown and the filter helpers) and uses the exact WINDIVERT_ADDRESS layout,
so the Linux backend shares :class:`pydivert.windivert_dll.WinDivertAddress`
with the Windows one.  The library is self-contained (the BPF object and
libbpf are linked in) and is bundled as ``pydivert/bpf/libebpfdivert.so``.
"""

import ctypes
import os
from ctypes import POINTER, c_char_p, c_int, c_int16, c_size_t, c_uint32, c_uint64, c_void_p

from pydivert.windivert_dll.structs import WinDivertAddress

# Kernel statistics counters (ebpfdivert_shared.h STAT_*).
STAT_NAMES = ("diverted", "dropped", "sniffed", "parsing_errors", "ringbuf_full", "queue_full", "too_big")


class OpenOpts(ctypes.Structure):
    """struct ebpfdivert_open_opts"""

    _fields_ = [
        ("sz", c_size_t),
        ("ifnames", POINTER(c_char_p)),
        ("ring_bytes", c_uint32),
    ]


_FUNCTIONS = {
    "ebpfdivert_version": ([], c_char_p),
    "ebpfdivert_open": ([c_char_p, c_int, c_int16, c_uint64, POINTER(OpenOpts)], c_void_p),
    "ebpfdivert_recv": (
        [c_void_p, c_void_p, c_uint32, POINTER(c_uint32), POINTER(WinDivertAddress), c_int],
        c_int,
    ),
    "ebpfdivert_recv_ex": (
        [c_void_p, c_void_p, c_uint32, POINTER(c_uint32), POINTER(WinDivertAddress), POINTER(c_uint32), c_int],
        c_int,
    ),
    "ebpfdivert_send": ([c_void_p, c_void_p, c_uint32, POINTER(c_uint32), POINTER(WinDivertAddress)], c_int),
    "ebpfdivert_send_ex": (
        [c_void_p, c_void_p, c_uint32, POINTER(c_uint32), POINTER(WinDivertAddress), c_uint32],
        c_int,
    ),
    "ebpfdivert_shutdown": ([c_void_p, c_int], c_int),
    "ebpfdivert_close": ([c_void_p], c_int),
    "ebpfdivert_set_param": ([c_void_p, c_int, c_uint64], c_int),
    "ebpfdivert_get_param": ([c_void_p, c_int, POINTER(c_uint64)], c_int),
    "ebpfdivert_get_event_fd": ([c_void_p], c_int),
    "ebpfdivert_get_handle_stats": ([c_void_p, POINTER(c_uint64), c_int], c_int),
    "ebpfdivert_unregister": ([], c_int),
    "ebpfdivert_strerror": ([c_int], c_char_p),
    "ebpfdivert_helper_compile_filter": ([c_char_p, c_int, POINTER(c_char_p), POINTER(c_uint32)], c_int),
    "ebpfdivert_helper_eval_filter": ([c_char_p, c_void_p, c_uint32, POINTER(WinDivertAddress)], c_int),
    "ebpfdivert_helper_format_filter": ([c_char_p, c_int, c_char_p, c_uint32], c_int),
    "ebpfdivert_helper_calc_checksums": ([c_void_p, c_uint32, POINTER(WinDivertAddress), c_uint64], c_int),
    "ebpfdivert_helper_hash_packet": ([c_void_p, c_uint32, c_uint64], c_uint64),
}


def _candidates() -> list[str]:
    paths = []
    env = os.environ.get("PYDIVERT_EBPFDIVERT_LIB")
    if env:
        paths.append(env)
    paths.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "libebpfdivert.so"))
    paths.append("libebpfdivert.so.0")
    return paths


def _load() -> ctypes.CDLL | None:
    for path in _candidates():
        try:
            lib = ctypes.CDLL(path, use_errno=True)
        except OSError:
            continue
        try:
            for name, (argtypes, restype) in _FUNCTIONS.items():
                fn = getattr(lib, name)
                fn.argtypes = argtypes
                fn.restype = restype
        except AttributeError:
            # An older libebpfdivert without the handle API.
            continue
        return lib
    return None


libebpfdivert = _load()


def strerror(err: int) -> str:
    if libebpfdivert is not None:
        msg = libebpfdivert.ebpfdivert_strerror(err)
        if msg:
            return msg.decode(errors="replace")
    return os.strerror(abs(err))  # pragma: no cover


__all__ = ["libebpfdivert", "OpenOpts", "STAT_NAMES", "WinDivertAddress", "strerror"]
