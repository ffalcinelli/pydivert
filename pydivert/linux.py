# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from __future__ import annotations

import asyncio
import atexit
import logging
import queue
import socket
import subprocess
import threading
from typing import Any

from pydivert.base import BaseDivert
from pydivert.consts import Direction, Flag, Layer
from pydivert.filter import transpile_to_rules
from pydivert.packet import Packet

logger = logging.getLogger(__name__)

try:
    from netfilterqueue import NetfilterQueue as NFQ  # type: ignore
except ImportError:
    NFQ = None

class NetFilterQueue(BaseDivert):
    """
    Linux implementation of the Divert interface using **NetFilterQueue** (NFQUEUE) and **iptables**.

    This class provides a WinDivert-compatible API on Linux systems. It achieves packet interception
    by dynamically adding `iptables` rules that target specific traffic and redirect it to a
    user-space queue.

    **Requirements:**
    - `libnetfilter-queue` installed on the system.
    - `NetFilterQueue` Python library.
    - Root/Administrator privileges to modify `iptables` and bind to NFQUEUE.

    **How it works:**
    1.  When `.open()` is called, it translates the WinDivert-style `filter` string into `iptables` rules.
    2.  It inserts these rules at the top of the `INPUT`, `OUTPUT`, and `FORWARD` chains.
    3.  A background thread runs the NFQUEUE event loop, which places intercepted packets into a thread-safe queue.
    4.  `.recv()` and `.recv_async()` read from this internal queue.
    5.  `.send()` and `.send_async()` either accept/modify the original packet (if it was intercepted)
        or inject a new packet using a raw socket.
    6.  `.close()` removes the `iptables` rules and unbinds the queue.

    .. warning::
       Be careful with broad filters (like "true") as they might intercept SSH traffic and
       disconnect your session if not handled properly. This implementation automatically
       tries to exclude port 22 traffic for safety.
    """
    _instances: set[NetFilterQueue] = set()

    def __init__(
        self, filter: str = "true", layer: Layer = Layer.NETWORK, priority: int = 0, flags: Flag = Flag.DEFAULT
    ) -> None:
        super().__init__(filter, layer, priority, flags)
        self._nfqueue: Any = None
        # Use priority to offset queue number to avoid collisions in parallel tests
        self._queue_num = 0 + (priority % 1000)
        self._queue: queue.Queue[Packet] = queue.Queue(maxsize=10000)
        self._async_queue: asyncio.Queue[Packet] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._translated_filter = self.filter
        self._applied_rules: list[list[str]] = []
        self._stop_event = threading.Event()
        NetFilterQueue._instances.add(self)

    @classmethod
    def _cleanup_all(cls):
        for instance in list(cls._instances):
            try:
                instance.close()
            except Exception:
                pass

    def _parse_filter_to_iptables(self):
        rules = []
        if self._translated_filter.lower() == "true":
            # Intercept everything EXCEPT SSH to avoid breaking Vagrant
            rules.append((["INPUT", "OUTPUT", "FORWARD"], ["-p", "tcp", "!", "--dport", "22", "!", "--sport", "22"]))
            rules.append((["INPUT", "OUTPUT", "FORWARD"], ["-p", "udp"]))
            rules.append((["INPUT", "OUTPUT", "FORWARD"], ["-p", "icmp"]))
            return rules

        parsed_rules = transpile_to_rules(self._translated_filter)
        for rule_dict in parsed_rules:
            if not rule_dict:
                rules.append((["INPUT", "OUTPUT", "FORWARD"], []))
                continue
            rules.extend(self._build_iptables_rule(rule_dict))
        return rules

    def _build_iptables_rule(self, rule_dict):
        ipt_args = []
        chains = ["INPUT", "OUTPUT", "FORWARD"]
        if "proto" in rule_dict:
            ipt_args.extend(["-p", rule_dict["proto"]])
        if "dport" in rule_dict:
            ipt_args.extend(["--dport", rule_dict["dport"]])
        if "sport" in rule_dict:
            ipt_args.extend(["--sport", rule_dict["sport"]])
        if "srcaddr" in rule_dict:
            ipt_args.extend(["-s", rule_dict["srcaddr"]])
        if "dstaddr" in rule_dict:
            ipt_args.extend(["-d", rule_dict["dstaddr"]])

        if rule_dict.get("direction") == "inbound":
            chains = ["INPUT", "FORWARD"]
        elif rule_dict.get("direction") == "outbound":
            chains = ["OUTPUT", "FORWARD"]

        if rule_dict.get("loopback"):
            return [
                (["INPUT"], ["-i", "lo"]),
                (["OUTPUT"], ["-o", "lo"])
            ]
        return [(chains, ipt_args)]

    def open(self) -> None:
        if NFQ is None:
            raise ImportError("netfilterqueue library not found. Install it with 'pip install NetFilterQueue'.")

        self._bind_nfq()
        logger.info("Opening NetFilterQueue %d with filter: %s", self._queue_num, self._translated_filter)
        self._cleanup_stale_rules()

        self._applied_rules = self._parse_filter_to_iptables()
        try:
            for chains, r in self._applied_rules:
                for chain in chains:
                    subprocess.run(
                        ["iptables", "-I", chain, *r, "-j", "NFQUEUE", "--queue-num", str(self._queue_num)],
                        check=True, capture_output=True
                    )
        except Exception as e:
            self.close()
            raise RuntimeError(f"Failed to add iptables rule: {e}") from e

        self._thread = threading.Thread(target=self._run_loop, name=f"pydivert-nfq-{self._queue_num}", daemon=True)
        self._thread.start()

    def _bind_nfq(self):
        if NFQ is None:
            raise ImportError("netfilterqueue library not found.")
        nfq = NFQ()
        for _i in range(10):
            try:
                nfq.bind(self._queue_num, self._callback)
                self._nfqueue = nfq
                return
            except OSError:
                self._queue_num += 1
        raise OSError("Failed to bind to any NFQueue. Are you root?")

    def _cleanup_stale_rules(self):
        for chain in ["INPUT", "OUTPUT", "FORWARD"]:
            try:
                if subprocess.run(["iptables", "-L", chain], capture_output=True).returncode != 0:
                    continue
                res = subprocess.run(["iptables", "-S", chain], capture_output=True, text=True)
                if res.returncode == 0:
                    pattern = f"--queue-num {self._queue_num}"
                    to_delete = [line for line in res.stdout.splitlines() if pattern in line]
                    for line in to_delete:
                        delete_cmd = line.replace("-A ", "-D ").split()
                        subprocess.run(["iptables", *delete_cmd[1:]], check=False)
            except Exception:
                pass

    def _remove_rules(self):
        for chains, r in self._applied_rules:
            try:
                for chain in chains:
                    # Check if chain exists before attempting to delete
                    if subprocess.run(["iptables", "-L", chain], capture_output=True).returncode != 0:
                        continue
                    subprocess.run(
                        ["iptables", "-D", chain, *r, "-j", "NFQUEUE", "--queue-num", str(self._queue_num)],
                        check=False, stderr=subprocess.DEVNULL
                    )
            except Exception:
                pass
        self._applied_rules = []

    def _run_loop(self):
        nfqueue = self._nfqueue
        if nfqueue is None:
            return
        try:
            nfqueue.run()
        except Exception as e:
            # Avoid logging error if we're closing
            if not self._stop_event.is_set():
                logger.error(f"NFQueue loop error: {e}")

    def _callback(self, pkt):
        raw = pkt.get_payload()

        # Determine direction and loopback from interface info
        indev = getattr(pkt, "indev", 0)
        outdev = getattr(pkt, "outdev", 0)

        # Interface index 1 is almost always 'lo' on Linux.
        is_loopback = (indev == 1 or outdev == 1)

        # Direction
        if outdev > 0 and indev == 0:
            direction = Direction.OUTBOUND
        else:
            direction = Direction.INBOUND

        p = Packet(raw, direction=direction, loopback=is_loopback)
        p._nfq_pkt = pkt

        # Robust loopback detection fallback
        if not p.is_loopback and (p.src_addr == "127.0.0.1" or p.dst_addr == "127.0.0.1"):
            # Update packet metadata if it's clearly loopback but missing from iface info
            p.is_loopback = True

        # User space filtering
        if p.matches(self._translated_filter):
            try:
                self._queue.put(p, block=False)
                # If there's an active async loop, notify it
                if self._loop and self._async_queue:
                    self._loop.call_soon_threadsafe(self._async_queue.put_nowait, p)
            except (queue.Full, asyncio.QueueFull):
                logger.warning("Packet queue full, dropping intercepted packet to prevent OOM")
                pkt.accept()
        else:
            pkt.accept()

    def close(self) -> None:
        if self._nfqueue:
            logger.info("Closing NetFilterQueue %d", self._queue_num)
            self._stop_event.set()
            temp_nfq = self._nfqueue
            self._nfqueue = None # Mark as closed first
            try:
                temp_nfq.unbind()
            except Exception:
                pass
        self._remove_rules()
        if self in NetFilterQueue._instances:
            NetFilterQueue._instances.remove(self)

    @property
    def is_open(self) -> bool:
        return self._nfqueue is not None

    def recv(self) -> Packet:
        while self.is_open:
            try:
                return self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
        raise RuntimeError("Queue is not open.")

    async def recv_async(self) -> Packet:
        if not self.is_open:
            raise RuntimeError("Queue is not open.")

        if self._async_queue is None:
            self._loop = asyncio.get_running_loop()
            self._async_queue = asyncio.Queue(maxsize=10000)
            # Drain current sync queue into async queue
            try:
                while True:
                    self._async_queue.put_nowait(self._queue.get_nowait())
            except (queue.Empty, asyncio.QueueFull):
                pass

        return await self._async_queue.get()

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        if not self.is_open:
            raise RuntimeError("Queue is not open.")

        if recalculate_checksum:
            packet.recalculate_checksums()

        nfq_pkt = getattr(packet, '_nfq_pkt', None)
        if nfq_pkt:
            raw = packet.raw.tobytes() if hasattr(packet.raw, "tobytes") else packet.raw
            try:
                nfq_pkt.set_payload(raw)
                nfq_pkt.accept()
            except Exception as e:
                logger.error(f"Failed to accept/modify NFQ packet: {e}")
        else:
            # Inject new packet using raw socket
            try:
                if packet.ipv4:
                    # For loopback injection on Linux, we might need a different approach
                    # if the destination is 127.0.0.1
                    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
                        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                        raw_bytes = packet.raw.tobytes() if hasattr(packet.raw, "tobytes") else packet.raw
                        s.sendto(raw_bytes, (packet.dst_addr, 0))
            except Exception as e:
                logger.error(f"Failed to inject packet: {e}")
        return len(packet.raw)

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        return self.send(packet, recalculate_checksum)

atexit.register(NetFilterQueue._cleanup_all)
