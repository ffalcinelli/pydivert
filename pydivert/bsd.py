# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from __future__ import annotations

import asyncio
import atexit
import logging
import queue
import re
import socket
import subprocess
import sys
import threading
import time

from pydivert.base import BaseDivert
from pydivert.consts import Direction, Flag, Layer
from pydivert.packet import Packet

logger = logging.getLogger(__name__)

class Divert(BaseDivert):
    """
    FreeBSD implementation of the Divert interface using **Divert Sockets** and **ipfw**.
    """
    _instances: set[Divert] = set()

    def __init__(
        self, filter: str = "true", layer: Layer = Layer.NETWORK, priority: int = 0, flags: Flag = Flag.DEFAULT
    ) -> None:
        super().__init__(filter, layer, priority, flags)
        self._socket: socket.socket | None = None
        self._port = 8888 + (priority % 1000)
        self._queue: queue.Queue[Packet] = queue.Queue(maxsize=10000)
        self._async_queue: asyncio.Queue[Packet] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._translated_filter = self.filter
        self._applied_rules_with_numbers: list[tuple[int, str]] = []
        Divert._instances.add(self)

    @classmethod
    def cleanup_all(cls):
        for instance in list(cls._instances):
            try:
                instance.close()
            except Exception:
                pass

    def _parse_filter_to_ipfw(self):
        rules = []
        filter_str = self._translated_filter
        prefix = f"divert {self._port}"

        # Check if loopback is explicitly or implicitly involved
        is_loopback = re.search(r'\bloopback\b', filter_str, re.I) or "127.0.0.1" in filter_str
        suffix = " via lo0" if is_loopback else ""

        if filter_str.lower() == "true":
            rules.append(f"{prefix} tcp from any to any not dst-port 22 not src-port 22{suffix}")
            rules.append(f"{prefix} udp from any to any{suffix}")
            rules.append(f"{prefix} icmp from any to any{suffix}")
        elif filter_str.lower() == "tcp":
            rules.append(f"{prefix} tcp from any to any not dst-port 22 not src-port 22{suffix}")
        elif filter_str.lower() == "udp":
            rules.append(f"{prefix} udp from any to any{suffix}")
        else:
            parts = re.split(r'\s+or\s+|\s*\|\|\s*', filter_str, flags=re.IGNORECASE)
            for part in parts:
                part = part.strip('() ')
                m = re.match(r'(tcp|udp)\.(DstPort|SrcPort)\s*==\s*(\d+)', part, flags=re.IGNORECASE)
                if m:
                    proto = m.group(1).lower()
                    port_type = m.group(2).lower()
                    port = m.group(3)
                    if port_type == 'dstport':
                        rules.append(f"{prefix} {proto} from any to any {port}{suffix}")
                    else:
                        rules.append(f"{prefix} {proto} from any {port} to any{suffix}")
                elif part.lower() == "loopback":
                    rules.append(f"{prefix} ip from any to any via lo0")
                elif part.lower() == "outbound":
                    rules.append(f"{prefix} ip from any to any out{suffix}")
        return rules

    def open(self) -> None:
        if self.is_open:
            raise RuntimeError("Divert handle is already open.")

        IPPROTO_DIVERT = getattr(socket, 'IPPROTO_DIVERT', 258)
        for _i in range(100):
            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_DIVERT)
                self._socket.bind(('0.0.0.0', self._port))
                break
            except (OSError, PermissionError) as e:
                if getattr(e, 'errno', None) == 48 or "Address already in use" in str(e):
                    self._port += 1
                    continue
                raise OSError(f"Failed to open divert socket on port {self._port}: {e}. Are you root?") from e
        else:
             raise OSError("Failed to find a free port for divert socket.")

        if sys.platform.startswith("freebsd"):
            self._applied_rules_with_numbers = []
            rules = self._parse_filter_to_ipfw()
            base_rule_num = 50 + (self._priority % 100)
            for idx, r in enumerate(rules):
                rule_num = base_rule_num + idx
                try:
                    subprocess.run(["ipfw", "add", str(rule_num)] + r.split(), check=True, capture_output=True)
                    self._applied_rules_with_numbers.append((rule_num, r))
                except Exception as e:
                    self.close()
                    raise RuntimeError(f"Failed to apply ipfw rule: {e}") from e

        self._thread = threading.Thread(target=self._run_loop, name=f"pydivert-bsd-{self._port}", daemon=True)
        self._thread.start()

    def _run_loop(self):
        sock = self._socket
        if not sock:
            return
        while not self._stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                if not data:
                    continue
                # addr is (ip_addr, interface_index) on FreeBSD
                ip_addr, port = addr if addr and len(addr) >= 2 else ('0.0.0.0', 0)
                direction = Direction.OUTBOUND if port == 0 else Direction.INBOUND
                is_loopback = (ip_addr == '0.0.0.0' or ip_addr == '127.0.0.1')

                p = Packet(data, direction=direction, loopback=is_loopback)
                p._bsd_addr = addr

                if p.matches(self._translated_filter):
                    self._queue.put(p)
                    if self._loop and self._async_queue:
                        self._loop.call_soon_threadsafe(self._async_queue.put_nowait, p)
                else:
                    # Packet didn't match our filter, re-inject immediately
                    sock.sendto(data, addr)
            except Exception:
                if self._stop_event.is_set():
                    break
                time.sleep(0.01)

    def close(self) -> None:
        self._stop_event.set()
        if self._socket:
            if sys.platform.startswith("freebsd"):
                for num, _ in self._applied_rules_with_numbers:
                    try:
                        subprocess.run(["ipfw", "delete", str(num)], check=False, capture_output=True)
                    except Exception:
                        pass
            self._applied_rules_with_numbers = []

            # Unblock the recv loop by closing the socket
            temp_sock = self._socket
            self._socket = None
            temp_sock.close()

        if self in Divert._instances:
            Divert._instances.remove(self)

    @property
    def is_open(self) -> bool:
        return self._socket is not None

    def recv(self) -> Packet:
        while self.is_open or not self._queue.empty():
            try:
                return self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
        raise RuntimeError("Handle is closed.")

    async def recv_async(self) -> Packet:
        if not self.is_open:
            raise RuntimeError("Handle is closed.")

        if self._async_queue is None:
            self._loop = asyncio.get_running_loop()
            self._async_queue = asyncio.Queue(maxsize=10000)
            try:
                while True:
                    self._async_queue.put_nowait(self._queue.get_nowait())
            except (queue.Empty, asyncio.QueueFull):
                pass

        return await self._async_queue.get()

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        sock = self._socket
        if not sock:
            raise RuntimeError("Handle is closed.")

        if recalculate_checksum:
            packet.recalculate_checksums()

        addr = getattr(packet, '_bsd_addr', ('0.0.0.0', 0))
        try:
            raw_bytes = packet.raw.tobytes() if hasattr(packet.raw, "tobytes") else packet.raw
            return sock.sendto(raw_bytes, addr)
        except Exception as e:
            logger.error(f"Failed to send packet on BSD: {e}")
            raise

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        return self.send(packet, recalculate_checksum)

atexit.register(Divert.cleanup_all)
