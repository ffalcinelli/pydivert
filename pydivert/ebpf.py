# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import ctypes
import errno
import logging
import os
import socket
import threading
import time
from typing import Any

from .base import BaseDivert
from .bpf import (
    BpfRuleOpt,
    DivertPacketBuffer,
    libebpfdivert,
)
from .consts import (
    DEFAULT_PACKET_BUFFER_SIZE,
    Direction,
    Flag,
    Layer,
    Param,
)
from .filter import transpile_to_ebpf, transpile_to_rules
from .packet import Packet

# Define SO_MARK if missing (e.g. for type checking on non-Linux)
SO_MARK = getattr(socket, "SO_MARK", 36)

logger = logging.getLogger(__name__)

_ebpf_lock = threading.Lock()


def rule_to_opt(rule: dict[str, Any], sniff: bool, drop: bool) -> tuple[BpfRuleOpt, list[bytes]]:  # noqa: C901
    opt = BpfRuleOpt()
    refs = []

    def set_field(name: str, val: bytes):
        setattr(opt, name, val)
        refs.append(val)

    # 1. Action
    action = b"divert"
    if drop:
        action = b"drop"
    elif sniff:
        action = b"sniff"
    set_field("action", action)

    # 2. Proto
    proto = rule.get("proto") or rule.get("!proto")
    if proto:
        set_field("proto", str(proto).lower().encode())
    else:
        set_field("proto", b"any")

    # 3. Source IP
    src_ip = rule.get("srcaddr") or rule.get("!srcaddr")
    if src_ip:
        is_ipv6 = ":" in src_ip
        cidr = f"{src_ip}/128" if is_ipv6 else f"{src_ip}/32"
        set_field("src_ip_cidr", cidr.encode())
    else:
        set_field("src_ip_cidr", b"any")

    # 4. Destination IP
    dst_ip = rule.get("dstaddr") or rule.get("!dstaddr")
    if dst_ip:
        is_ipv6 = ":" in dst_ip
        cidr = f"{dst_ip}/128" if is_ipv6 else f"{dst_ip}/32"
        set_field("dst_ip_cidr", cidr.encode())
    else:
        set_field("dst_ip_cidr", b"any")

    # 5. Source Port
    src_port = rule.get("sport") or rule.get("!sport")
    if src_port is not None:
        set_field("src_port_range", f"{src_port}-{src_port}".encode())
    else:
        set_field("src_port_range", b"any")

    # 6. Destination Port
    dst_port = rule.get("dport") or rule.get("!dport")
    if dst_port is not None:
        set_field("dst_port_range", f"{dst_port}-{dst_port}".encode())
    else:
        set_field("dst_port_range", b"any")

    # 7. Direction
    direction = rule.get("direction") or rule.get("!direction")
    if direction:
        set_field("direction", direction.lower().encode())
    else:
        set_field("direction", b"any")

    # 8. Loopback
    loopback = rule.get("loopback") or rule.get("!loopback")
    if loopback is not None:
        set_field("loopback", b"yes" if loopback else b"no")
    else:
        set_field("loopback", b"any")

    # 9. TTL
    ttl = rule.get("ttl") or rule.get("!ttl")
    if ttl is not None:
        set_field("ttl", str(ttl).encode())
    else:
        set_field("ttl", b"any")

    # 10. TCP Flags
    flags = []
    for f in ["syn", "ack", "fin", "rst", "psh", "urg"]:
        if rule.get(f) is True:
            flags.append(f.upper())
    if flags:
        val = ",".join(flags).encode()
        set_field("tcp_flags", val)
        set_field("tcp_flags_mask", val)
    else:
        set_field("tcp_flags", b"any")
        set_field("tcp_flags_mask", b"any")

    # 11. Invert mask
    MATCH_SRC_IP = 1 << 0
    MATCH_DST_IP = 1 << 1
    MATCH_SRC_PORT = 1 << 2
    MATCH_DST_PORT = 1 << 3
    MATCH_PROTO = 1 << 4
    MATCH_DIRECTION = 1 << 5
    MATCH_LOOPBACK = 1 << 6
    MATCH_TTL = 1 << 11

    invert_mask = 0
    if "!srcaddr" in rule:
        invert_mask |= MATCH_SRC_IP
    if "!dstaddr" in rule:
        invert_mask |= MATCH_DST_IP
    if "!sport" in rule:
        invert_mask |= MATCH_SRC_PORT
    if "!dport" in rule:
        invert_mask |= MATCH_DST_PORT
    if "!proto" in rule:
        invert_mask |= MATCH_PROTO
    if "!direction" in rule:
        invert_mask |= MATCH_DIRECTION
    if "!loopback" in rule:
        invert_mask |= MATCH_LOOPBACK
    if "!ttl" in rule:
        invert_mask |= MATCH_TTL

    opt.invert_mask = invert_mask
    return opt, refs


class EBPFDivert(BaseDivert):
    """
    Linux implementation of the Divert interface using **eBPF** (via libebpfdivert).
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

        if libebpfdivert is None:
            raise ImportError("libebpfdivert missing on system.")
        self._handle = None
        self._raw_sock = self._raw_sock6 = None
        self._interfaces = kwargs.get("interfaces", None)
        self._tc_priority = 0
        self._mark = 0

    @staticmethod
    def register() -> None:
        """eBPF backend does not require explicit registration."""
        pass

    @staticmethod
    def is_registered() -> bool:
        """eBPF backend is always considered registered if libebpfdivert is available."""
        return libebpfdivert is not None

    @staticmethod
    def unregister() -> None:
        """
        Forcefully removes all PyDivert-related eBPF hooks from network interfaces.
        """
        if libebpfdivert:
            libebpfdivert.ebpfdivert_unload(None)

    @staticmethod
    def check_filter(filter: str, layer: Layer = Layer.NETWORK) -> tuple[bool, int, str]:
        """Check if a filter is valid for eBPF."""
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
        except Exception as e:
            logger.debug("Failed to check existing TC filters for max priority: %s", e)
        return max_prio + 1

    def _open_impl(self):  # noqa: C901
        with _ebpf_lock:
            obj_path = os.path.join(os.path.dirname(__file__), "bpf", "ebpfdivert.bpf.o")

            if self.priority == 0:
                self._tc_priority = self._get_next_priority()
            else:
                self._tc_priority = 30001 - self.priority

            self._mark = 0x4D490000 | (self._tc_priority & 0xFFFF)
            logger.debug(
                "EBPFDivert priority=%d -> tc_priority=%d, mark=0x%08x",
                self.priority,
                self._tc_priority,
                self._mark,
            )

            if Flag.SEND_ONLY not in self.flags:
                ifname = None
                if self._interfaces:
                    if len(self._interfaces) == 1:
                        ifname = self._interfaces[0].encode()
                    else:
                        ifname = b"all"

                logger.debug("Loading BPF object and driver via libebpfdivert: %s", obj_path)
                ret = libebpfdivert.ebpfdivert_load(ifname, obj_path.encode(), self._tc_priority)
                if ret != 0:
                    raise RuntimeError("Failed to load eBPFDivert BPF object.")

                self._handle = libebpfdivert.ebpfdivert_open(self._tc_priority)
                if not self._handle:
                    libebpfdivert.ebpfdivert_unload(ifname)
                    raise RuntimeError("Failed to create eBPFDivert handle.")

                # Clear rules
                libebpfdivert.ebpfdivert_rules_clear()

                # Transpile and load rules
                logger.debug("Transpiling filter: %s", self.filter)
                is_sniff = (Flag.SNIFF in self.flags) or (self.layer in (Layer.FLOW, Layer.SOCKET, Layer.REFLECT))
                rules = transpile_to_rules(self.filter)

                rule_idx = 0
                for rule in rules[:64]:
                    if "false" in rule:
                        continue
                    opt, refs = rule_to_opt(rule, sniff=is_sniff, drop=(Flag.DROP in self.flags))
                    ret = libebpfdivert.ebpfdivert_rules_add_extended(rule_idx, ctypes.byref(opt))
                    if ret == 0:
                        rule_idx += 1
                    else:
                        logger.warning("Failed to add filter rule %d: %d", rule_idx, ret)

            if Flag.RECV_ONLY not in self.flags:
                self._raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                self._raw_sock.setsockopt(socket.SOL_SOCKET, SO_MARK, self._mark)
                self._raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

                try:
                    self._raw_sock6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
                    self._raw_sock6.setsockopt(socket.SOL_SOCKET, SO_MARK, self._mark)
                    if hasattr(socket, "IPV6_HDRINCL"):
                        self._raw_sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_HDRINCL, 1)
                except OSError:
                    self._raw_sock6 = None

    def _close_impl(self):
        self._is_open = False

        with _ebpf_lock:
            if self._handle:
                libebpfdivert.ebpfdivert_close(self._handle)
                self._handle = None

            ifname = None
            if self._interfaces:
                if len(self._interfaces) == 1:
                    ifname = self._interfaces[0].encode()
                else:
                    ifname = b"all"

            if libebpfdivert:
                libebpfdivert.ebpfdivert_unload(ifname)

            if self._raw_sock:
                self._raw_sock.close()
                self._raw_sock = None
            if self._raw_sock6:
                self._raw_sock6.close()
                self._raw_sock6 = None

    def _recv_impl(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        if Flag.SEND_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is send-only")

        buf = DivertPacketBuffer()
        start = time.time()

        while self.is_open:
            ret = libebpfdivert.ebpfdivert_recv(self._handle, ctypes.byref(buf), ctypes.sizeof(buf), 10)
            if ret == 0:
                pkt_len = buf.header.pkt_len
                ifindex = buf.header.ifindex
                direction = Direction.INBOUND if buf.header.direction == 1 else Direction.OUTBOUND
                l2_len = buf.header.l2_len

                raw_frame = bytes(buf.data)[:pkt_len]
                l2_header = raw_frame[:l2_len]

                if self._interfaces and len(self._interfaces) > 1:
                    try:
                        current_ifname = socket.if_indextoname(ifindex)
                        if current_ifname not in self._interfaces:
                            continue
                    except OSError:
                        continue

                p = Packet(
                    raw_frame[l2_len:],
                    direction=direction,
                    interface=ifindex,
                    layer=self.layer,
                )

                if p.src_addr == "127.0.0.1" or p.dst_addr == "127.0.0.1" or p.src_addr == "::1" or p.dst_addr == "::1":
                    p.is_loopback = True

                p._l2_header = l2_header
                return p

            if timeout is not None and (time.time() - start) > timeout:
                raise TimeoutError("The read operation timed out")

            time.sleep(0.001)

        raise OSError(errno.EBADF, "Handle closed while receiving")

    def _recv_batch_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:  # noqa: C901
        if Flag.SEND_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is send-only")

        packets = []
        try:
            p = self._recv_impl(bufsize, timeout)
            packets.append(p)
            while len(packets) < count:
                try:
                    buf = DivertPacketBuffer()
                    ret = libebpfdivert.ebpfdivert_recv(self._handle, ctypes.byref(buf), ctypes.sizeof(buf), 0)
                    if ret == 0:
                        pkt_len = buf.header.pkt_len
                        ifindex = buf.header.ifindex
                        direction = Direction.INBOUND if buf.header.direction == 1 else Direction.OUTBOUND
                        l2_len = buf.header.l2_len
                        raw_frame = bytes(buf.data)[:pkt_len]

                        if self._interfaces and len(self._interfaces) > 1:
                            try:
                                current_ifname = socket.if_indextoname(ifindex)
                                if current_ifname not in self._interfaces:
                                    continue
                            except OSError:
                                continue

                        p2 = Packet(
                            raw_frame[l2_len:],
                            direction=direction,
                            interface=ifindex,
                            layer=self.layer,
                        )
                        if (
                            p2.src_addr == "127.0.0.1"
                            or p2.dst_addr == "127.0.0.1"
                            or p2.src_addr == "::1"
                            or p2.dst_addr == "::1"
                        ):
                            p2.is_loopback = True
                        p2._l2_header = raw_frame[:l2_len]
                        packets.append(p2)
                    else:
                        break
                except Exception:
                    break
        except TimeoutError:
            if not packets:
                raise
        return packets

    def _send_impl(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        if Flag.RECV_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is receive-only")

        if recalculate_checksum:
            packet.recalculate_checksums()

        l2_header = getattr(packet, "_l2_header", None)
        if l2_header is not None:
            buf = DivertPacketBuffer()
            payload = bytes(packet.raw)
            full_frame = bytes(l2_header) + payload

            buf.header.pkt_len = len(full_frame)
            buf.header.ifindex = packet.interface[0]
            buf.header.direction = 1 if packet.direction == Direction.INBOUND else 2
            buf.header.l2_len = len(l2_header)
            buf.header.cap_len = len(full_frame)

            ctypes.memmove(buf.data, full_frame, min(len(full_frame), 2048))

            ret = libebpfdivert.ebpfdivert_send(self._handle, ctypes.byref(buf))
            if ret != 0:
                raise OSError(-ret, os.strerror(-ret))
            return len(payload)

        dst_addr = packet.dst_addr
        if dst_addr is None:
            logger.warning("Cannot send packet with unknown destination address")
            return 0

        sock = self._raw_sock6 if packet.ipv6 else self._raw_sock
        if not sock:
            msg = "IPv6 raw socket not available" if packet.ipv6 else "IPv4 raw socket not available"
            raise OSError(errno.EAFNOSUPPORT, msg)

        if packet.ipv6:
            scope_id = 0
            if dst_addr == "::1":
                try:
                    scope_id = socket.if_nametoindex("lo")
                except OSError:
                    scope_id = 0
            return sock.sendto(packet.raw, (dst_addr, 0, 0, scope_id))

        return sock.sendto(packet.raw, (dst_addr, 0))

    def _stats_impl(self):
        if not self._handle:
            return {"diverted": 0, "dropped": 0, "sniffed": 0}

        stats = (ctypes.c_uint64 * 6)()
        ret = libebpfdivert.ebpfdivert_get_stats(stats, 6)
        if ret == 0:
            return {
                "diverted": stats[0],  # STAT_DIVERTED
                "dropped": stats[1],   # STAT_DROPPED
                "sniffed": stats[2],   # STAT_SNIFFED
            }
        return {"diverted": 0, "dropped": 0, "sniffed": 0}

    async def _recv_async_impl(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        import asyncio

        if Flag.SEND_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is send-only")

        return await asyncio.to_thread(self._recv_impl, bufsize, timeout)

    async def _send_async_impl(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        import asyncio

        if Flag.RECV_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is receive-only")

        return await asyncio.to_thread(self._send_impl, packet, recalculate_checksum)

    async def _recv_batch_async_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        packets = []
        try:
            p = await self._recv_async_impl(bufsize, timeout)
            packets.append(p)
            while len(packets) < count:
                # Retrieve any immediately buffered packets
                packets_list = self._recv_batch_impl(count - len(packets), bufsize, 0)
                if not packets_list:
                    break
                packets.extend(packets_list)
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
            except Exception as e:
                logger.debug("Failed to send packet in batch: %s", e)
                continue
        return count

    async def _send_batch_async_impl(self, packets: list[Packet], recalculate_checksum: bool) -> int:
        import asyncio

        return await asyncio.to_thread(self._send_batch_impl, packets, recalculate_checksum)

    def set_param(self, name: Param, value: int) -> int:
        if name == Param.QUEUE_LEN:
            if not self._handle:
                raise RuntimeError("Divert handle is not open")
            ret = libebpfdivert.ebpfdivert_set_max_queue_size(self._handle, value)
            if ret != 0:
                raise OSError(-ret, os.strerror(-ret))
            self._max_queue_size = value
            return 0
        else:
            raise NotImplementedError("Parameter not supported on eBPF backend.")

    def get_param(self, name: Param) -> int:
        if name == Param.QUEUE_LEN:
            return getattr(self, "_max_queue_size", 1024)
        else:
            raise NotImplementedError("Parameter not supported on eBPF backend.")

