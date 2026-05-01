# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import ctypes
import logging

from .structs import (
    PERF_BUF_CB,
    RINGBUF_CB,
    BpfFilterRule,
    BpfMap,
    BpfObject,
    BpfTcHook,
    BpfTcOpts,
    PerfBufferOpts,
)

logger = logging.getLogger(__name__)

# Attempt to load libbpf
try:
    libbpf = ctypes.CDLL("libbpf.so.1")
except OSError:
    try:
        libbpf = ctypes.CDLL("libbpf.so")
    except OSError:
        libbpf = None

if libbpf:
    libbpf.bpf_object__open_file.restype = ctypes.POINTER(BpfObject)
    libbpf.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

    libbpf.bpf_object__load.restype = ctypes.c_int
    libbpf.bpf_object__load.argtypes = [ctypes.POINTER(BpfObject)]

    libbpf.bpf_object__find_map_by_name.restype = ctypes.POINTER(BpfMap)
    libbpf.bpf_object__find_map_by_name.argtypes = [ctypes.POINTER(BpfObject), ctypes.c_char_p]

    libbpf.bpf_map__fd.restype = ctypes.c_int
    libbpf.bpf_map__fd.argtypes = [ctypes.POINTER(BpfMap)]

    libbpf.bpf_object__find_program_by_name.restype = ctypes.c_void_p
    libbpf.bpf_object__find_program_by_name.argtypes = [ctypes.POINTER(BpfObject), ctypes.c_char_p]

    libbpf.bpf_program__fd.restype = ctypes.c_int
    libbpf.bpf_program__fd.argtypes = [ctypes.c_void_p]

    libbpf.perf_buffer__new.restype = ctypes.c_void_p
    libbpf.perf_buffer__new.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.POINTER(PerfBufferOpts)]

    libbpf.perf_buffer__consume.restype = ctypes.c_int
    libbpf.perf_buffer__consume.argtypes = [ctypes.c_void_p]

    libbpf.perf_buffer__epoll_fd.restype = ctypes.c_int
    libbpf.perf_buffer__epoll_fd.argtypes = [ctypes.c_void_p]

    libbpf.perf_buffer__free.restype = None
    libbpf.perf_buffer__free.argtypes = [ctypes.c_void_p]

    libbpf.ring_buffer__new.restype = ctypes.c_void_p
    libbpf.ring_buffer__new.argtypes = [ctypes.c_int, RINGBUF_CB, ctypes.c_void_p, ctypes.c_void_p]

    libbpf.ring_buffer__poll.restype = ctypes.c_int
    libbpf.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]

    libbpf.ring_buffer__consume.restype = ctypes.c_int
    libbpf.ring_buffer__consume.argtypes = [ctypes.c_void_p]

    libbpf.ring_buffer__epoll_fd.restype = ctypes.c_int
    libbpf.ring_buffer__epoll_fd.argtypes = [ctypes.c_void_p]

    libbpf.ring_buffer__free.restype = None
    libbpf.ring_buffer__free.argtypes = [ctypes.c_void_p]

    libbpf.bpf_map_update_elem.restype = ctypes.c_int
    libbpf.bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]

    libbpf.bpf_object__close.restype = None
    libbpf.bpf_object__close.argtypes = [ctypes.POINTER(BpfObject)]

    libbpf.bpf_tc_hook_create.restype = ctypes.c_int
    libbpf.bpf_tc_hook_create.argtypes = [ctypes.POINTER(BpfTcHook)]

    libbpf.bpf_tc_hook_destroy.restype = ctypes.c_int
    libbpf.bpf_tc_hook_destroy.argtypes = [ctypes.POINTER(BpfTcHook)]

    libbpf.bpf_tc_attach.restype = ctypes.c_int
    libbpf.bpf_tc_attach.argtypes = [ctypes.POINTER(BpfTcHook), ctypes.POINTER(BpfTcOpts)]

    libbpf.bpf_tc_detach.restype = ctypes.c_int
    libbpf.bpf_tc_detach.argtypes = [ctypes.POINTER(BpfTcHook), ctypes.POINTER(BpfTcOpts)]

__all__ = [
    "libbpf",
    "BpfObject",
    "BpfMap",
    "BpfTcHook",
    "BpfTcOpts",
    "BpfFilterRule",
    "PerfBufferOpts",
    "PERF_BUF_CB",
    "RINGBUF_CB",
]
