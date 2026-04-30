# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import ctypes
import os
import socket
import time
from typing import Any, cast

from pydivert.base import BaseDivert
from pydivert.bpf import (
    RINGBUF_CB,
    BpfFilterRule,
    BpfTcHook,
    BpfTcOpts,
    libbpf,
)
from pydivert.consts import (
    DEFAULT_PACKET_BUFFER_SIZE,
    LOOP_PREVENTION_MARK,
    Direction,
    Flag,
    Layer,
)
from pydivert.filter import transpile_to_ebpf
from pydivert.packet import Packet

# Define SO_MARK if missing (e.g. for type checking on non-Linux)
SO_MARK = getattr(socket, "SO_MARK", 36)


class EBPFDivert(BaseDivert):
    """
    Linux implementation of the Divert interface using **eBPF**.
    """

    def __init__(
        self, filter: str = "true", layer: Layer = Layer.NETWORK, priority: int = 0, flags: Flag = Flag.DEFAULT
    ) -> None:
        super().__init__(filter, layer, priority, flags)
        if libbpf is None:
            raise ImportError("libbpf missing on system.")
        self._obj = self._ringbuf = self._raw_sock = None
        self._queue: list[Packet] = []
        self._ifname = "lo"

    def open(self):
        if self.is_open:
            raise RuntimeError("Handle already open.")

        bpf = cast(Any, libbpf)
        obj_path = os.path.join(os.path.dirname(__file__), "bpf", "pydivert.bpf.o")
        self._obj = bpf.bpf_object__open_file(obj_path.encode(), None)
        if not self._obj or bpf.bpf_object__load(self._obj) != 0:
            raise RuntimeError("Failed to load BPF object.")

        # Rules
        rules_map_ptr = bpf.bpf_object__find_map_by_name(self._obj, b"rules_map")
        if rules_map_ptr:
            map_fd = bpf.bpf_map__fd(rules_map_ptr)
            ebpf_rules = transpile_to_ebpf(self.filter)
            for i, rule_data in enumerate(ebpf_rules[:32]):
                rule = BpfFilterRule()
                rule.src_ip = rule_data.get("src_ip", 0)
                rule.dst_ip = rule_data.get("dst_ip", 0)
                rule.src_port = rule_data.get("src_port", 0)
                rule.dst_port = rule_data.get("dst_port", 0)
                rule.proto = rule_data.get("proto", 0)
                rule.match_mask = rule_data.get("match_mask", 0)
                key = ctypes.c_uint32(i)
                bpf.bpf_map_update_elem(map_fd, ctypes.byref(key), ctypes.byref(rule), 0)

        # Ringbuf
        map_ptr = bpf.bpf_object__find_map_by_name(self._obj, b"pcap_ringbuf")
        if not map_ptr:
            raise RuntimeError("pcap_ringbuf map missing.")

        self._cb = RINGBUF_CB(self._ring_callback)
        self._ringbuf = bpf.ring_buffer__new(bpf.bpf_map__fd(map_ptr), self._cb, None, None)
        if not self._ringbuf:
            raise RuntimeError("Failed to create ring buffer.")

        # TC
        prog = bpf.bpf_object__find_program_by_name(self._obj, b"tc_divert_ingress")
        ifindex = socket.if_nametoindex(self._ifname)
        self._hook = BpfTcHook(sz=ctypes.sizeof(BpfTcHook), ifindex=ifindex, attach_point=1)
        bpf.bpf_tc_hook_create(ctypes.byref(self._hook))
        self._opts = BpfTcOpts(sz=ctypes.sizeof(BpfTcOpts), prog_fd=bpf.bpf_program__fd(prog))
        ret = bpf.bpf_tc_attach(ctypes.byref(self._hook), ctypes.byref(self._opts))
        if ret != 0:
            raise RuntimeError(f"Failed to attach TC (ret={ret})")

        self._raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self._raw_sock.setsockopt(socket.SOL_SOCKET, SO_MARK, LOOP_PREVENTION_MARK)

    def _ring_callback(self, ctx, data, size):
        if size < 4:
            return 0
        import struct

        raw_full = ctypes.string_at(data, size)
        pkt_len = struct.unpack("I", raw_full[:4])[0]
        # Skip prefix and Ethernet header
        p = Packet(raw_full[18 : 18 + (pkt_len - 14)], direction=Direction.INBOUND)
        if p.matches(self.filter):
            self._queue.append(p)
        else:
            self.send(p, False)
        return 0

    def close(self):
        bpf = cast(Any, libbpf)
        if self._obj:
            bpf.bpf_tc_detach(ctypes.byref(self._hook), ctypes.byref(self._opts))
            if self._ringbuf:
                bpf.ring_buffer__free(self._ringbuf)
            bpf.bpf_object__close(self._obj)
            self._obj = self._ringbuf = None
        if self._raw_sock:
            self._raw_sock.close()
            self._raw_sock = None

    @property
    def is_open(self):
        return self._obj is not None

    def recv(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        if not self.is_open:
            raise RuntimeError("Not open")

        bpf = cast(Any, libbpf)
        start = time.time()
        while not self._queue and self.is_open:
            bpf.ring_buffer__poll(self._ringbuf, 10)
            if timeout and (time.time() - start) > timeout:
                raise TimeoutError()
        return self._queue.pop(0)

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        if not self.is_open or not self._raw_sock:
            raise RuntimeError("Not open")
        if recalculate_checksum:
            packet.recalculate_checksums()
        return self._raw_sock.sendto(packet.raw.tobytes(), (packet.dst_addr, 0))

    async def recv_async(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        import asyncio

        return await asyncio.to_thread(self.recv, bufsize, timeout)

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        return self.send(packet, recalculate_checksum)
