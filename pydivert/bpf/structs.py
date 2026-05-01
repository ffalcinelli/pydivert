# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import ctypes


class BpfObject(ctypes.Structure):
    pass


class BpfMap(ctypes.Structure):
    pass


class BpfTcHook(ctypes.Structure):
    _fields_ = [
        ("sz", ctypes.c_size_t),
        ("ifindex", ctypes.c_int),
        ("attach_point", ctypes.c_uint),
        ("parent", ctypes.c_uint),
        ("reserved", ctypes.c_uint * 24),
    ]


class BpfTcOpts(ctypes.Structure):
    _fields_ = [
        ("sz", ctypes.c_size_t),
        ("prog_fd", ctypes.c_int),
        ("prog_id", ctypes.c_uint),
        ("handle", ctypes.c_uint),
        ("priority", ctypes.c_uint),
        ("reserved", ctypes.c_uint * 20),
    ]


PERF_BUF_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)


class PerfBufferOpts(ctypes.Structure):
    _fields_ = [
        ("sz", ctypes.c_size_t),
        ("sample_cb", PERF_BUF_CB),
        ("lost_cb", ctypes.c_void_p),
        ("ctx", ctypes.c_void_p),
    ]


class BpfFilterRule(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("match_mask", ctypes.c_uint16),
        ("proto", ctypes.c_uint8),
        ("direction", ctypes.c_uint8),
        ("loopback", ctypes.c_uint8),
        ("padding", ctypes.c_uint8),
    ]


RINGBUF_CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
