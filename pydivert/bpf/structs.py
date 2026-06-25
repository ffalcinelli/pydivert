# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import ctypes


class BpfObject(ctypes.Structure):
    """Opaque structure for BPF objects."""


class BpfMap(ctypes.Structure):
    """Opaque structure for BPF maps."""


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
        ("flags", ctypes.c_uint32),
        ("prog_id", ctypes.c_uint32),
        ("handle", ctypes.c_uint32),
        ("priority", ctypes.c_uint32),
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
        ("src_mask", ctypes.c_uint32),
        ("dst_mask", ctypes.c_uint32),
        ("src_port_start", ctypes.c_uint16),
        ("src_port_end", ctypes.c_uint16),
        ("dst_port_start", ctypes.c_uint16),
        ("dst_port_end", ctypes.c_uint16),
        ("match_mask", ctypes.c_uint16),
        ("invert_mask", ctypes.c_uint16),
        ("proto", ctypes.c_uint8),
        ("direction", ctypes.c_uint8),
        ("loopback", ctypes.c_uint8),
        ("ttl", ctypes.c_uint8),
        ("tcp_flags", ctypes.c_uint8),
        ("tcp_flags_mask", ctypes.c_uint8),
    ]


class BpfRuleOpt(ctypes.Structure):
    _fields_ = [
        ("proto", ctypes.c_char_p),
        ("src_ip_cidr", ctypes.c_char_p),
        ("dst_ip_cidr", ctypes.c_char_p),
        ("src_port_range", ctypes.c_char_p),
        ("dst_port_range", ctypes.c_char_p),
        ("action", ctypes.c_char_p),
        ("direction", ctypes.c_char_p),
        ("loopback", ctypes.c_char_p),
        ("ttl", ctypes.c_char_p),
        ("tcp_flags", ctypes.c_char_p),
        ("tcp_flags_mask", ctypes.c_char_p),
        ("invert_mask", ctypes.c_uint16),
    ]


class DivertPktHeader(ctypes.Structure):
    _fields_ = [
        ("pkt_len", ctypes.c_uint32),
        ("ifindex", ctypes.c_uint32),
        ("direction", ctypes.c_uint16),
        ("l2_len", ctypes.c_uint16),
        ("cap_len", ctypes.c_uint32),
    ]


class DivertPacketBuffer(ctypes.Structure):
    _fields_ = [
        ("header", DivertPktHeader),
        ("data", ctypes.c_uint8 * 2048),
    ]


RINGBUF_CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
LIBBPF_PRINT_CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p)
