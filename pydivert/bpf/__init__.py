# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import ctypes
import ctypes.util
import logging
import os
from typing import Any

from .structs import (
    BpfRuleOpt,
    DivertPacketBuffer,
    DivertPktHeader,
)

logger = logging.getLogger(__name__)

# Attempt to load libebpfdivert
libebpf_path = ctypes.util.find_library("ebpfdivert")
if not libebpf_path:
    # Check if it's bundled in the local directory
    bundled_path = os.path.join(os.path.dirname(__file__), "libebpfdivert.so")
    if os.path.exists(bundled_path):
        libebpf_path = bundled_path

libebpfdivert: Any = None

if libebpf_path:
    try:
        libebpfdivert = ctypes.CDLL(libebpf_path)
    except OSError:
        pass

if libebpfdivert:
    libebpfdivert.ebpfdivert_load.restype = ctypes.c_int
    libebpfdivert.ebpfdivert_load.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]

    libebpfdivert.ebpfdivert_unload.restype = ctypes.c_int
    libebpfdivert.ebpfdivert_unload.argtypes = [ctypes.c_char_p]

    libebpfdivert.ebpfdivert_rules_clear.restype = ctypes.c_int
    libebpfdivert.ebpfdivert_rules_clear.argtypes = []

    libebpfdivert.ebpfdivert_rules_add_extended.restype = ctypes.c_int
    libebpfdivert.ebpfdivert_rules_add_extended.argtypes = [ctypes.c_int, ctypes.POINTER(BpfRuleOpt)]

    libebpfdivert.ebpfdivert_open.restype = ctypes.c_void_p
    libebpfdivert.ebpfdivert_open.argtypes = [ctypes.c_uint32]

    libebpfdivert.ebpfdivert_recv.restype = ctypes.c_int
    libebpfdivert.ebpfdivert_recv.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(DivertPacketBuffer),
        ctypes.c_size_t,
        ctypes.c_int,
    ]

    libebpfdivert.ebpfdivert_send.restype = ctypes.c_int
    libebpfdivert.ebpfdivert_send.argtypes = [ctypes.c_void_p, ctypes.POINTER(DivertPacketBuffer)]

    libebpfdivert.ebpfdivert_close.restype = None
    libebpfdivert.ebpfdivert_close.argtypes = [ctypes.c_void_p]

    libebpfdivert.ebpfdivert_get_stats.restype = ctypes.c_int
    libebpfdivert.ebpfdivert_get_stats.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_int]

    libebpfdivert.ebpfdivert_set_max_queue_size.restype = ctypes.c_int
    libebpfdivert.ebpfdivert_set_max_queue_size.argtypes = [ctypes.c_void_p, ctypes.c_int]

__all__ = [
    "libebpfdivert",
    "BpfRuleOpt",
    "DivertPktHeader",
    "DivertPacketBuffer",
]
