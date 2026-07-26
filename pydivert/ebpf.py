# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import ctypes
import errno
import logging
import os
import socket
import threading
import time
from collections import deque
from typing import Any, cast

from .base import BaseDivert
from .bpf import (
    LIBBPF_PRINT_CB,
    RINGBUF_CB,
    BpfFilterRule,
    BpfTcHook,
    BpfTcOpts,
    DivertPacketBuffer,
    libbpf,
)
from .consts import (
    DEFAULT_PACKET_BUFFER_SIZE,
    Direction,
    Flag,
    Layer,
)
from .filter import transpile_to_ebpf
from .packet import Packet

# Define SO_MARK if missing (e.g. for type checking on non-Linux)
SO_MARK = getattr(socket, "SO_MARK", 36)

logger = logging.getLogger(__name__)


# Silence libbpf's confusing warnings (like exclusivity flag on TC)
def _libbpf_print(level, format_str, args):
    if os.environ.get("PYDIVERT_DEBUG_BPF") == "1":
        print(f"libbpf: {format_str.decode('utf-8', 'replace').strip()}")  # pragma: no cover
    return 0


_libbpf_print_cb = LIBBPF_PRINT_CB(_libbpf_print)
if libbpf:
    try:
        libbpf.libbpf_set_print(_libbpf_print_cb)
    except Exception as e:  # pragma: no cover
        logger.debug("Failed to set libbpf print callback: %s", e)

_ebpf_lock = threading.Lock()
_initialized_hooks = set()


class EBPFDivert(BaseDivert):
    """
    Linux implementation of the Divert interface using **eBPF**.
    """

    def __init__(
        self,
        filter: str = "true",
        layer: Layer = Layer.NETWORK,
        priority: int = 0,
        flags: Flag = Flag.DEFAULT,
        **kwargs,
    ) -> None:
        super().__init__(filter, layer, priority, flags, **kwargs)
        if layer not in (Layer.NETWORK, Layer.FLOW, Layer.SOCKET):
            raise NotImplementedError(f"Layer {layer} is not supported on Linux yet.")

        if libbpf is None:
            raise ImportError("libbpf missing on system.")
        self._obj = self._ringbuf = self._raw_sock = self._raw_sock6 = None
        self._queue: deque[Packet] = deque()
        self._hooks: list[tuple[BpfTcHook, BpfTcOpts]] = []
        self._interfaces = kwargs.get("interfaces", None)
        self._tc_priority = 0
        self._mark = 0

    @staticmethod
    def register() -> None:
        """eBPF backend does not require explicit registration."""
        pass  # pragma: no cover

    @staticmethod
    def is_registered() -> bool:
        """eBPF backend is always considered registered if libbpf is available."""
        return libbpf is not None

    @staticmethod
    def unregister() -> None:  # pragma: no cover
        """
        Forcefully removes all PyDivert-related eBPF hooks from all network interfaces.
        This provides parity with WinDivert.unregister() and can be used for emergency cleanup.
        """
        import json
        import os
        import subprocess

        try:
            interfaces = os.listdir("/sys/class/net")
        except OSError:
            return

        for ifname in interfaces:
            for hook in ["ingress", "egress"]:
                try:
                    # Query existing filters on the interface
                    output = subprocess.check_output(
                        ["sudo", "tc", "-j", "filter", "show", "dev", ifname, hook],
                        stderr=subprocess.DEVNULL,
                    )
                    if not output:
                        continue
                    filters = json.loads(output)
                    for f in filters:
                        # Identify PyDivert filters by the BPF program name
                        options = f.get("options", {})
                        bpf_name = options.get("bpf_name", "")
                        if "tc_divert_ingre" in bpf_name or "tc_divert_egres" in bpf_name:
                            pref = f.get("pref")
                            handle = options.get("handle")
                            if pref and handle:
                                # Surgical deletion of the specific filter
                                subprocess.run(
                                    [
                                        "sudo",
                                        "tc",
                                        "filter",
                                        "del",
                                        "dev",
                                        ifname,
                                        hook,
                                        "pref",
                                        str(pref),
                                        "handle",
                                        str(handle),
                                        "bpf",
                                    ],
                                    check=False,
                                )
                except Exception as e:  # pragma: no cover
                    logger.debug("Failed to delete stale TC filter: %s", e)
                    continue

    @staticmethod
    def check_filter(filter: str, layer: Layer = Layer.NETWORK) -> tuple[bool, int, str]:
        """Check if a filter is valid for eBPF."""
        # For now, we assume filters are valid if they can be transpiled
        try:
            transpile_to_ebpf(filter)
            return True, 0, ""
        except Exception as e:
            return False, -1, str(e)

    @staticmethod
    def _get_next_priority() -> int:
        """Find the highest existing PyDivert TC priority and return the next one."""
        import json
        import subprocess

        max_prio = 29999
        try:
            # Check loopback interface as a reference
            output = subprocess.check_output(
                ["sudo", "tc", "-j", "filter", "show", "dev", "lo", "ingress"],
                stderr=subprocess.DEVNULL,
            )
            if output:
                filters = json.loads(output)
                for f in filters:
                    options = f.get("options", {})
                    if "tc_divert" in options.get("bpf_name", ""):
                        max_prio = max(max_prio, f.get("pref", 0))
        except Exception as e:  # pragma: no cover
            logger.debug("Failed to check existing TC filters for max priority: %s", e)
        return max_prio + 1

    def _open_impl(self):  # noqa: C901
        with _ebpf_lock:
            bpf = cast(Any, libbpf)
            obj_path = os.path.join(os.path.dirname(__file__), "bpf", "ebpfdivert.bpf.o")

            # In Windows, priority 0 means default.
            # In TC, priority 1 is highest. We map our priority to TC priority.
            # If priority is 0, we use a default priority that allows multiple handles.
            if self.priority == 0:
                self._tc_priority = self._get_next_priority()
            else:
                # Map WinDivert priority range (30000 to -30000) to TC range (1 to 65535)
                # WinDivert: 30000 -> TC: 1, 0 -> TC: 30001, -30000 -> TC: 60001
                self._tc_priority = 30001 - self.priority

            self._mark = 0x4D490000 | (self._tc_priority & 0xFFFF)
            logger.debug(
                "EBPFDivert priority=%d -> tc_priority=%d, mark=0x%08x", self.priority, self._tc_priority, self._mark
            )

            if Flag.SEND_ONLY not in self.flags:
                logger.debug("Loading BPF object: %s", obj_path)
                self._obj = bpf.bpf_object__open_file(obj_path.encode(), None)
                if not self._obj or bpf.bpf_object__load(self._obj) != 0:
                    raise RuntimeError("Failed to load BPF object.")  # pragma: no cover

                # Update config map with our priority
                config_map_ptr = bpf.bpf_object__find_map_by_name(self._obj, b"config_map")
                if config_map_ptr:
                    config_fd = bpf.bpf_map__fd(config_map_ptr)
                    key = ctypes.c_uint32(0)
                    val = ctypes.c_uint32(self._tc_priority)
                    bpf.bpf_map_update_elem(config_fd, ctypes.byref(key), ctypes.byref(val), 0)

                # Ringbuf
                map_ptr = bpf.bpf_object__find_map_by_name(self._obj, b"pcap_ringbuf")
                if not map_ptr:
                    raise RuntimeError("pcap_ringbuf map missing.")  # pragma: no cover

                self._cb = RINGBUF_CB(self._ring_callback)
                self._ringbuf = bpf.ring_buffer__new(bpf.bpf_map__fd(map_ptr), self._cb, None, None)
                if not self._ringbuf:
                    raise RuntimeError("Failed to create ring buffer.")  # pragma: no cover

                self._epoll_fd = bpf.ring_buffer__epoll_fd(self._ringbuf)
                self._recv_futures: list[Any] = []

                # Load filter rules
                logger.debug("Transpiling filter: %s", self.filter)
                is_sniff = (Flag.SNIFF in self.flags) or (self.layer in (Layer.FLOW, Layer.SOCKET, Layer.REFLECT))
                ebpf_filter_rules = transpile_to_ebpf(self.filter, sniff=is_sniff, drop=(Flag.DROP in self.flags))
                rules_map_ptr = bpf.bpf_object__find_map_by_name(self._obj, b"filter_rules")
                if rules_map_ptr:
                    rules_fd = bpf.bpf_map__fd(rules_map_ptr)

                    # Clear map (up to 16 rules unrolled in C)
                    empty_rule = BpfFilterRule()
                    for i in range(16):
                        key = ctypes.c_uint32(i)
                        bpf.bpf_map_update_elem(rules_fd, ctypes.byref(key), ctypes.byref(empty_rule), 0)

                    # Fill map
                    for i, rule in enumerate(ebpf_filter_rules[:16]):
                        key = ctypes.c_uint32(i)
                        c_rule = BpfFilterRule(
                            src_ip=rule["src_ip"],
                            dst_ip=rule["dst_ip"],
                            src_port=rule["src_port"],
                            dst_port=rule["dst_port"],
                            match_mask=rule["match_mask"],
                            invert_mask=rule["invert_mask"],
                            proto=rule["proto"],
                            direction=rule["direction"],
                            loopback=rule["loopback"],
                            ttl=rule["ttl"],
                            tcp_flags=rule["tcp_flags"],
                            tcp_flags_mask=rule["tcp_flags_mask"],
                        )
                        bpf.bpf_map_update_elem(rules_fd, ctypes.byref(key), ctypes.byref(c_rule), 0)

                # Attach TC hooks
                prog_ingress = bpf.bpf_object__find_program_by_name(self._obj, b"tc_divert_ingress")
                prog_egress = bpf.bpf_object__find_program_by_name(self._obj, b"tc_divert_egress")

                if not prog_ingress or not prog_egress:
                    raise RuntimeError("Failed to find BPF programs.")  # pragma: no cover

                for ifindex, ifname in socket.if_nameindex():
                    if self._interfaces is not None and ifname not in self._interfaces:
                        continue  # pragma: no cover

                    logger.debug("Attaching TC hooks to %s (%d)", ifname, ifindex)

                    # Ingress
                    hook_ingress = BpfTcHook(sz=ctypes.sizeof(BpfTcHook), ifindex=ifindex, attach_point=1)
                    try:
                        bpf.bpf_tc_hook_create(ctypes.byref(hook_ingress))
                    except Exception as e:  # pragma: no cover
                        logger.debug("Failed to create TC hook (may already exist): %s", e)

                    opts_ingress = BpfTcOpts(
                        sz=ctypes.sizeof(BpfTcOpts),
                        prog_fd=bpf.bpf_program__fd(prog_ingress),
                        flags=0,
                        priority=self._tc_priority,
                    )
                    if bpf.bpf_tc_attach(ctypes.byref(hook_ingress), ctypes.byref(opts_ingress)) == 0:
                        # Copy the objects to ensure they are not overwritten in the loop
                        h = BpfTcHook()
                        ctypes.memmove(ctypes.byref(h), ctypes.byref(hook_ingress), ctypes.sizeof(BpfTcHook))
                        o = BpfTcOpts()
                        ctypes.memmove(ctypes.byref(o), ctypes.byref(opts_ingress), ctypes.sizeof(BpfTcOpts))
                        self._hooks.append((h, o))

                    # Egress
                    hook_egress = BpfTcHook(sz=ctypes.sizeof(BpfTcHook), ifindex=ifindex, attach_point=2)
                    try:
                        bpf.bpf_tc_hook_create(ctypes.byref(hook_egress))
                    except Exception as e:  # pragma: no cover
                        logger.debug("Failed to create TC hook (may already exist): %s", e)

                    opts_egress = BpfTcOpts(
                        sz=ctypes.sizeof(BpfTcOpts),
                        prog_fd=bpf.bpf_program__fd(prog_egress),
                        flags=0,
                        priority=self._tc_priority,
                    )
                    if bpf.bpf_tc_attach(ctypes.byref(hook_egress), ctypes.byref(opts_egress)) == 0:
                        # Copy the objects to ensure they are not overwritten in the loop
                        h = BpfTcHook()
                        ctypes.memmove(ctypes.byref(h), ctypes.byref(hook_egress), ctypes.sizeof(BpfTcHook))
                        o = BpfTcOpts()
                        ctypes.memmove(ctypes.byref(o), ctypes.byref(opts_egress), ctypes.sizeof(BpfTcOpts))
                        self._hooks.append((h, o))

                if not self._hooks:
                    raise RuntimeError("Failed to attach eBPF hooks to any interface.")  # pragma: no cover

            if Flag.RECV_ONLY not in self.flags:
                self._raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                self._raw_sock.setsockopt(socket.SOL_SOCKET, SO_MARK, self._mark)
                self._raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

                try:
                    self._raw_sock6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
                    self._raw_sock6.setsockopt(socket.SOL_SOCKET, SO_MARK, self._mark)
                    if hasattr(socket, "IPV6_HDRINCL"):
                        self._raw_sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_HDRINCL, 1)  # pragma: no cover
                except OSError:  # pragma: no cover
                    # IPv6 might not be supported
                    self._raw_sock6 = None  # pragma: no cover

    def _ring_callback(self, ctx, data, size):
        buf = DivertPacketBuffer.from_address(data)
        pkt_len = buf.header.pkt_len
        ifindex = buf.header.ifindex
        direction = Direction.INBOUND if buf.header.direction == 1 else Direction.OUTBOUND
        l2_len = buf.header.l2_len

        # Extract captured data, skipping prefix and any L2 header if needed
        # Since we load from offset 0, we have the full frame including L2
        raw_frame = bytes(buf.data)[:pkt_len]

        # Trust the l2_len provided by BPF
        actual_l2_len = l2_len

        # If BPF couldn't determine it, fallback to the heuristic
        if actual_l2_len == 0 and pkt_len > 0:
            if raw_frame[0] == 0x45 or (raw_frame[0] & 0xF0) == 0x60:  # pragma: no cover
                actual_l2_len = 0  # pragma: no cover
            elif pkt_len > 4 and (raw_frame[4] == 0x45 or (raw_frame[4] & 0xF0) == 0x60):  # pragma: no cover
                actual_l2_len = 4  # pragma: no cover
            elif pkt_len > 4 and raw_frame[:4] in (  # pragma: no cover
                b"\x02\x00\x00\x00",
                b"\x00\x00\x00\x02",
            ):
                actual_l2_len = 4  # pragma: no cover
            elif pkt_len > 14 and (raw_frame[14] == 0x45 or (raw_frame[14] & 0xF0) == 0x60):  # pragma: no cover
                actual_l2_len = 14  # pragma: no cover

        p = Packet(
            raw_frame[actual_l2_len:],
            direction=direction,
            interface=ifindex,
            layer=self.layer,
        )

        # Basic loopback detection based on IP addresses
        if p.src_addr == "127.0.0.1" or p.dst_addr == "127.0.0.1" or p.src_addr == "::1" or p.dst_addr == "::1":
            p.is_loopback = True

        if self.layer == Layer.FLOW:
            # Emulate WinDivert FLOW data for parity
            from pydivert.windivert_dll.structs import WinDivertAddress  # pragma: no cover

            flow_data = WinDivertAddress._Union._Flow()  # pragma: no cover
            flow_data.Protocol = p.protocol[0] or 0  # pragma: no cover
            flow_data.LocalPort = p.src_port or 0  # pragma: no cover
            flow_data.RemotePort = p.dst_port or 0  # pragma: no cover
            # LocalAddr/RemoteAddr are harder as they are arrays, but we can try
            p.flow = flow_data  # pragma: no cover

        self._queue.append(p)
        return 0

    def _close_impl(self):
        # Signal that we are closing
        self._is_open = False

        # Cancel any pending futures
        if hasattr(self, "_recv_futures") and self._recv_futures:
            for fut in self._recv_futures:  # pragma: no cover
                if not fut.done():  # pragma: no cover
                    fut.set_exception(RuntimeError("Handle closed"))  # pragma: no cover
            self._recv_futures.clear()  # pragma: no cover

        with _ebpf_lock:
            bpf = cast(Any, libbpf)
            if self._obj is not True and self._obj:
                for hook, opts in self._hooks:
                    # To detach, handle and priority must be set to exactly what they were during attach
                    # We ensure this by memmoving the state immediately after attachment.
                    bpf.bpf_tc_detach(ctypes.byref(hook), ctypes.byref(opts))
                self._hooks.clear()

                if self._ringbuf:
                    # Give some time for poll() to exit
                    ringbuf = self._ringbuf
                    self._ringbuf = None
                    time.sleep(0.05)
                    bpf.ring_buffer__free(ringbuf)

                bpf.bpf_object__close(self._obj)
            self._obj = None
            if self._raw_sock:
                self._raw_sock.close()
                self._raw_sock = None
            if self._raw_sock6:
                self._raw_sock6.close()
                self._raw_sock6 = None

    def _recv_impl(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        if Flag.SEND_ONLY in self.flags:
            raise OSError(socket.EBADF, "Handle is send-only")  # pragma: no cover

        bpf = cast(Any, libbpf)
        start = time.time()
        while not self._queue and self.is_open:
            if self._ringbuf:
                bpf.ring_buffer__poll(self._ringbuf, 10)
            else:  # pragma: no cover
                time.sleep(0.001)  # pragma: no cover

            if timeout and (time.time() - start) > timeout:
                raise TimeoutError("The read operation timed out")

        if not self._queue:
            raise OSError(socket.EBADF, "Handle closed while receiving")

        return self._queue.popleft()

    def _recv_batch_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        if Flag.SEND_ONLY in self.flags:  # pragma: no cover
            raise OSError(socket.EBADF, "Handle is send-only")  # pragma: no cover

        packets = []  # pragma: no cover
        try:  # pragma: no cover
            p = self._recv_impl(bufsize, timeout)  # pragma: no cover
            packets.append(p)  # pragma: no cover
            while len(packets) < count and self._queue:  # pragma: no cover
                packets.append(self._queue.popleft())  # pragma: no cover
        except TimeoutError:  # pragma: no cover
            if not packets:  # pragma: no cover
                raise  # pragma: no cover
        return packets  # pragma: no cover

    def _stats_impl(self):
        if self._obj is True or not self._obj:
            return {"diverted": 0, "dropped": 0, "sniffed": 0}

        bpf = cast(Any, libbpf)
        map_ptr = bpf.bpf_object__find_map_by_name(self._obj, b"stats_map")
        if not map_ptr:
            return {"diverted": 0, "dropped": 0, "sniffed": 0}  # pragma: no cover

        fd = bpf.bpf_map__fd(map_ptr)
        num_cpus = bpf.libbpf_num_possible_cpus()
        if num_cpus <= 0:
            num_cpus = os.cpu_count() or 1  # pragma: no cover

        def get_stat(key_idx):
            key = ctypes.c_uint32(key_idx)
            # PERCPU_ARRAY map values are returned as an array of values, one per CPU.
            # Each value is 8-byte aligned.
            value_type = ctypes.c_uint64 * num_cpus
            values = value_type()
            if bpf.bpf_map_lookup_elem(fd, ctypes.byref(key), ctypes.byref(values)) == 0:
                return sum(values)
            return 0  # pragma: no cover

        return {
            "diverted": get_stat(0),  # STAT_DIVERTED
            "dropped": get_stat(1),  # STAT_DROPPED
            "sniffed": get_stat(2),  # STAT_SNIFFED
        }

    def _send_impl(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        if Flag.RECV_ONLY in self.flags:
            raise OSError(socket.EBADF, "Handle is receive-only")  # pragma: no cover

        if recalculate_checksum:
            packet.recalculate_checksums()

        dst_addr = packet.dst_addr
        if dst_addr is None:
            logger.warning("Cannot send packet with unknown destination address")  # pragma: no cover
            return 0

        # Choose socket and possibly bind to interface
        sock = self._raw_sock6 if packet.ipv6 else self._raw_sock
        if not sock:
            msg = "IPv6 raw socket not available" if packet.ipv6 else "IPv4 raw socket not available"
            raise OSError(errno.EAFNOSUPPORT, msg)

        # For loopback re-injection, some kernels require explicit binding or
        # handling to ensure the packet hits the right hooks.
        if packet.ipv6:
            scope_id = 0  # pragma: no cover
            if dst_addr == "::1":  # pragma: no cover
                try:  # pragma: no cover
                    scope_id = socket.if_nametoindex("lo")  # pragma: no cover
                except OSError:  # pragma: no cover
                    scope_id = 0  # pragma: no cover
            return sock.sendto(packet.raw, (dst_addr, 0, 0, scope_id))  # pragma: no cover

        return sock.sendto(packet.raw, (dst_addr, 0))

    async def _recv_async_impl(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        import asyncio

        if Flag.SEND_ONLY in self.flags:
            raise OSError(socket.EBADF, "Handle is send-only")  # pragma: no cover

        return await asyncio.to_thread(self._recv_impl, bufsize, timeout)

    async def _send_async_impl(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        import asyncio

        if Flag.RECV_ONLY in self.flags:
            raise OSError(socket.EBADF, "Handle is receive-only")  # pragma: no cover

        return await asyncio.to_thread(self._send_impl, packet, recalculate_checksum)

    async def _recv_batch_async_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        packets = []
        try:
            p = await self._recv_async_impl(bufsize, timeout)
            packets.append(p)
            while len(packets) < count and self._queue:
                packets.append(self._queue.popleft())
        except (TimeoutError, Exception):  # pragma: no cover
            if not packets:  # pragma: no cover
                raise  # pragma: no cover
        return packets

    def _recv_batch_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        packets = []
        try:
            p = self._recv_impl(bufsize, timeout)
            packets.append(p)
            while len(packets) < count and self._queue:
                packets.append(self._queue.popleft())  # pragma: no cover
        except (TimeoutError, Exception):
            if not packets:
                raise
        return packets

    def _send_batch_impl(self, packets: list[Packet], recalculate_checksum: bool) -> int:
        count = 0
        for p in packets:
            try:
                if self._send_impl(p, recalculate_checksum) > 0:
                    count += 1
            except Exception as e:  # pragma: no cover
                logger.debug("Failed to send packet in batch: %s", e)
                continue
        return count

    async def _send_batch_async_impl(self, packets: list[Packet], recalculate_checksum: bool) -> int:
        import asyncio

        return await asyncio.to_thread(self._send_batch_impl, packets, recalculate_checksum)
