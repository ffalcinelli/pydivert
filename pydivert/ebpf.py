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
        if layer not in (Layer.NETWORK, Layer.FLOW, Layer.SOCKET):
            raise NotImplementedError(f"Layer {layer} is not supported on Linux yet.")
        
        if libbpf is None:
            raise ImportError("libbpf missing on system.")
        self._obj = self._ringbuf = self._raw_sock = self._raw_sock6 = None
        self._queue: list[Packet] = []
        self._ifname = "lo"

    def _open_impl(self):
        bpf = cast(Any, libbpf)
        obj_path = os.path.join(os.path.dirname(__file__), "bpf", "pydivert.bpf.o")
        
        if Flag.SEND_ONLY not in self.flags:
            self._obj = bpf.bpf_object__open_file(obj_path.encode(), None)
            if not self._obj or bpf.bpf_object__load(self._obj) != 0:
                raise RuntimeError("Failed to load BPF object.")

            # Ringbuf
            map_ptr = bpf.bpf_object__find_map_by_name(self._obj, b"pcap_ringbuf")
            if not map_ptr:
                raise RuntimeError("pcap_ringbuf map missing.")

            self._cb = RINGBUF_CB(self._ring_callback)
            self._ringbuf = bpf.ring_buffer__new(bpf.bpf_map__fd(map_ptr), self._cb, None, None)
            if not self._ringbuf:
                raise RuntimeError("Failed to create ring buffer.")
            
            self._epoll_fd = bpf.ring_buffer__epoll_fd(self._ringbuf)
            self._recv_futures: list[Any] = []

            # Load filter rules
            filter_rules = transpile_to_ebpf(self.filter, sniff=(Flag.SNIFF in self.flags), drop=(Flag.DROP in self.flags))
            rules_map_ptr = bpf.bpf_object__find_map_by_name(self._obj, b"filter_rules")
            if rules_map_ptr:
                rules_fd = bpf.bpf_map__fd(rules_map_ptr)
                for i, rule in enumerate(filter_rules):
                    if i >= 64:
                        break # Max 64 rules
                    c_rule = BpfFilterRule(
                        src_ip=rule["src_ip"],
                        dst_ip=rule["dst_ip"],
                        src_port=rule["src_port"],
                        dst_port=rule["dst_port"],
                        match_mask=rule["match_mask"],
                        proto=rule["proto"],
                        direction=rule["direction"],
                        loopback=rule["loopback"],
                        ttl=rule.get("ttl", 0),
                        tcp_flags=rule.get("tcp_flags", 0),
                        tcp_flags_mask=rule.get("tcp_flags_mask", 0)
                    )
                    key = ctypes.c_uint32(i)
                    bpf.bpf_map_update_elem(rules_fd, ctypes.byref(key), ctypes.byref(c_rule), 0)

            # TC Ingress
            prog_ingress = bpf.bpf_object__find_program_by_name(self._obj, b"tc_divert_ingress")
            ifindex = socket.if_nametoindex(self._ifname)
            self._hook_ingress = BpfTcHook(sz=ctypes.sizeof(BpfTcHook), ifindex=ifindex, attach_point=1)
            bpf.bpf_tc_hook_destroy(ctypes.byref(self._hook_ingress))
            bpf.bpf_tc_hook_create(ctypes.byref(self._hook_ingress))
            self._opts_ingress = BpfTcOpts(sz=ctypes.sizeof(BpfTcOpts), prog_fd=bpf.bpf_program__fd(prog_ingress))
            bpf.bpf_tc_attach(ctypes.byref(self._hook_ingress), ctypes.byref(self._opts_ingress))

            # TC Egress
            prog_egress = bpf.bpf_object__find_program_by_name(self._obj, b"tc_divert_egress")
            self._hook_egress = BpfTcHook(sz=ctypes.sizeof(BpfTcHook), ifindex=ifindex, attach_point=2)
            bpf.bpf_tc_hook_destroy(ctypes.byref(self._hook_egress))
            bpf.bpf_tc_hook_create(ctypes.byref(self._hook_egress))
            self._opts_egress = BpfTcOpts(sz=ctypes.sizeof(BpfTcOpts), prog_fd=bpf.bpf_program__fd(prog_egress))
            bpf.bpf_tc_attach(ctypes.byref(self._hook_egress), ctypes.byref(self._opts_egress))
        else:
            # SEND_ONLY: mark as "open" but without eBPF hooks
            self._obj = True # Sentinel

        if Flag.RECV_ONLY not in self.flags:
            self._raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self._raw_sock.setsockopt(socket.SOL_SOCKET, SO_MARK, LOOP_PREVENTION_MARK)

            try:
                self._raw_sock6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
                self._raw_sock6.setsockopt(socket.SOL_SOCKET, SO_MARK, LOOP_PREVENTION_MARK)
            except OSError:
                self._raw_sock6 = None

    def _ring_callback(self, ctx, data, size):
        if size < 5:
            return 0
        import struct

        raw_full = ctypes.string_at(data, size)
        pkt_len = struct.unpack("I", raw_full[:4])[0]
        direction_val = raw_full[4]
        direction = Direction.INBOUND if direction_val == 1 else Direction.OUTBOUND

        # Skip prefix (5 bytes) and Ethernet header (14 bytes)
        p = Packet(raw_full[19 : 19 + (pkt_len - 14)], direction=direction)

        # Mark as loopback if captured on lo
        if self._ifname == "lo":
            p.is_loopback = True

        self._queue.append(p)
        return 0

    def _close_impl(self):
        # Cancel any pending futures
        if hasattr(self, "_recv_futures") and self._recv_futures:
            for fut in self._recv_futures:
                if not fut.done():
                    fut.set_exception(RuntimeError("Handle closed"))
            self._recv_futures.clear()

        bpf = cast(Any, libbpf)
        if self._obj is not True and self._obj:
            if hasattr(self, "_hook_ingress"):
                bpf.bpf_tc_detach(ctypes.byref(self._hook_ingress), ctypes.byref(self._opts_ingress))
                bpf.bpf_tc_hook_destroy(ctypes.byref(self._hook_ingress))
            if hasattr(self, "_hook_egress"):
                bpf.bpf_tc_detach(ctypes.byref(self._hook_egress), ctypes.byref(self._opts_egress))
                bpf.bpf_tc_hook_destroy(ctypes.byref(self._hook_egress))
            if self._ringbuf:
                bpf.ring_buffer__free(self._ringbuf)
            bpf.bpf_object__close(self._obj)
        self._obj = self._ringbuf = None
        if self._raw_sock:
            self._raw_sock.close()
            self._raw_sock = None
        if self._raw_sock6:
            self._raw_sock6.close()
            self._raw_sock6 = None

    def _recv_impl(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        if Flag.SEND_ONLY in self.flags:
            raise OSError(socket.EBADF, "Handle is send-only")

        bpf = cast(Any, libbpf)
        start = time.time()
        while not self._queue and self.is_open:
            if self._ringbuf:
                bpf.ring_buffer__poll(self._ringbuf, 10)
            if timeout and (time.time() - start) > timeout:
                raise TimeoutError()
            if not self._ringbuf: # e.g. DROP mode or SEND_ONLY
                time.sleep(0.01)
        return self._queue.pop(0)

    def _recv_batch_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        if Flag.SEND_ONLY in self.flags:
            raise OSError(socket.EBADF, "Handle is send-only")

        packets = []
        start = time.time()
        bpf = cast(Any, libbpf)

        while len(packets) < count and self.is_open:
            while self._queue and len(packets) < count:
                packets.append(self._queue.pop(0))
            
            if len(packets) >= count:
                break
            
            if self._ringbuf:
                bpf.ring_buffer__poll(self._ringbuf, 10)
            
            if timeout and (time.time() - start) > timeout:
                break
            
            if not self._ringbuf:
                time.sleep(0.01)

        return packets

    def _send_impl(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        if Flag.RECV_ONLY in self.flags:
            raise OSError(socket.EBADF, "Handle is receive-only")
        if recalculate_checksum:
            packet.recalculate_checksums()
        
        if packet.ipv6:
            if not self._raw_sock6:
                raise OSError("IPv6 raw socket not available")
            # For IPv6 loopback, we might need the interface index (scope ID)
            scope_id = 0
            if packet.dst_addr == "::1":
                try:
                    scope_id = socket.if_nametoindex(self._ifname)
                except OSError:
                    scope_id = 0
            return self._raw_sock6.sendto(packet.raw, (packet.dst_addr, 0, 0, scope_id))
        
        if not self._raw_sock:
            raise RuntimeError("Not open")
        return self._raw_sock.sendto(packet.raw, (packet.dst_addr, 0))

    async def _recv_async_impl(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        import asyncio

        if Flag.SEND_ONLY in self.flags:
            raise OSError(socket.EBADF, "Handle is send-only")

        if self._queue:
            return self._queue.pop(0)

        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._recv_futures.append(future)

        def on_readable():
            if not self.is_open or not self._ringbuf:
                return
            bpf = cast(Any, libbpf)
            # Drain everything into self._queue
            bpf.ring_buffer__consume(self._ringbuf)

            # Distribute to waiting futures
            while self._queue and self._recv_futures:
                fut = self._recv_futures.pop(0)
                if not fut.done():
                    fut.set_result(self._queue.pop(0))

            # Stop monitoring if no more waiters
            if not self._recv_futures:
                loop.remove_reader(self._epoll_fd)

        loop.add_reader(self._epoll_fd, on_readable)

        try:
            if timeout:
                try:
                    return await asyncio.wait_for(future, timeout)
                except asyncio.TimeoutError:
                    raise TimeoutError() from None
            return await future
        finally:
            if future in self._recv_futures:
                self._recv_futures.remove(future)
            if not self._recv_futures:
                try:
                    loop.remove_reader(self._epoll_fd)
                except (ValueError, RuntimeError):
                    pass

    async def _recv_batch_async_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        import asyncio
        if Flag.SEND_ONLY in self.flags:
            raise OSError(socket.EBADF, "Handle is send-only")

        packets = []
        while self._queue and len(packets) < count:
            packets.append(self._queue.pop(0))
        
        if len(packets) >= count:
            return packets

        # Wait for more packets if needed
        while len(packets) < count:
            try:
                p = await self._recv_async_impl(bufsize, timeout)
                packets.append(p)
            except TimeoutError:
                break
        return packets

    async def _send_async_impl(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        import asyncio

        if Flag.RECV_ONLY in self.flags:
            raise OSError(socket.EBADF, "Handle is receive-only")

        return await asyncio.to_thread(self._send_impl, packet, recalculate_checksum)
