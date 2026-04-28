# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
"""
FreeBSD implementation of the Divert interface using **Divert Sockets**.

.. warning::
   FreeBSD support is currently **experimental**.
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import queue
import select
import socket
import subprocess
import sys
import threading
import time
from typing import Any

from pydivert.base import BaseDivert
from pydivert.consts import DEFAULT_PACKET_BUFFER_SIZE, Direction, Flag, Layer
from pydivert.filter import transpile_to_rules
from pydivert.packet import Packet

# Local alias for socket.socket to allow safe patching in tests
_Socket = socket.socket

logger = logging.getLogger(__name__)


class Divert(BaseDivert):
    """
    FreeBSD implementation of the Divert interface using **Divert Sockets** and **ipfw**.

    This backend intercepts network packets by dynamically adding `ipfw` firewall rules
    that direct matching traffic to a divert socket. When packets are read via `.recv()`,
    they are fetched from the socket; when sent via `.send()`, they are injected back
    into the network stack through the same socket.

    **Requirements:**
    - FreeBSD with `ipfw` and `ipdivert` kernel modules loaded.
    - Root privileges to create divert sockets and modify firewall rules.

    When the handle is closed, the injected `ipfw` rules are automatically removed.
    """

    _instances: set[Divert] = set()

    def __init__(
        self, filter: str = "true", layer: Layer = Layer.NETWORK, priority: int = 0, flags: Flag = Flag.DEFAULT
    ) -> None:
        super().__init__(filter, layer, priority, flags)
        self._socket: _Socket | None = None
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
    def cleanup_all(cls) -> None:
        for instance in list(cls._instances):
            try:
                instance.close()
            except OSError as e:  # pragma: no cover
                logger.debug("Failed to close Divert instance: %s", e)

    def _parse_filter_to_ipfw(self) -> list[str]:
        rules = []

        if self._translated_filter.lower() == "true":
            rules.append("tcp from any to any not dst-port 22 not src-port 22")
            rules.append("udp from any to any")
            rules.append("icmp from any to any")
            return rules

        parsed_rules = transpile_to_rules(self._translated_filter)
        for rule_dict in parsed_rules:
            if not rule_dict:
                # Broad fallback, but protect SSH
                rules.append("tcp from any to any not dst-port 22 not src-port 22")
                rules.append("udp from any to any")
                rules.append("icmp from any to any")
                continue

            # If the rule is for TCP/IP and doesn't specify ports, protect SSH
            proto = rule_dict.get("proto", "ip")
            if (proto in ("tcp", "ip")) and not rule_dict.get("dport") and not rule_dict.get("sport"):
                if proto == "ip":
                    # For broad IP rules, we must explicitly allow SSH to avoid interception
                    rules.append("tcp from any to any not dst-port 22 not src-port 22")
                    rules.append("udp from any to any")
                    rules.append("icmp from any to any")
                else:
                    rules.append(self._build_ipfw_rule(rule_dict, "") + " not dst-port 22 not src-port 22")
            else:
                rules.append(self._build_ipfw_rule(rule_dict, ""))
        return [r.strip() for r in rules]

    def _build_ipfw_rule(self, rule_dict: dict[str, Any], prefix: str) -> str:
        proto = rule_dict.get("proto", "ip")
        src = rule_dict.get("srcaddr", "any")
        dst = rule_dict.get("dstaddr", "any")

        parts = []
        if prefix:
            parts.append(prefix)
        parts.extend([proto, "from", src])
        if sport := rule_dict.get("sport"):
            parts.append(str(sport))

        parts.extend(["to", dst])
        if dport := rule_dict.get("dport"):
            parts.append(str(dport))

        direction = rule_dict.get("direction")
        if direction == "inbound":
            parts.append("in")
        elif direction == "outbound":
            parts.append("out")

        if rule_dict.get("loopback"):
            parts.append("via lo0")

        return " ".join(parts)

    def open(self) -> None:
        if self.is_open:  # pragma: no cover
            raise RuntimeError("Divert handle is already open.")

        IPPROTO_DIVERT = getattr(socket, "IPPROTO_DIVERT", 258)
        for _i in range(100):
            try:
                self._socket = _Socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_DIVERT)
                self._socket.bind(("0.0.0.0", self._port))
                break
            except (OSError, PermissionError) as e:  # pragma: no cover
                if getattr(e, "errno", None) == 48 or "Address already in use" in str(e):
                    self._port += 1
                    continue
                err_msg = f"Failed to open divert socket on port {self._port}: {e}. Are you root?"
                if hasattr(e, "errno") and e.errno is not None:
                    raise OSError(e.errno, err_msg) from e
                raise OSError(err_msg) from e
        else:  # pragma: no cover
            raise OSError("Failed to find a free port for divert socket.")

        if sys.platform.startswith("freebsd"):
            self._applied_rules_with_numbers = []
            rules = self._parse_filter_to_ipfw()
            base_rule_num = 50 + (self._priority % 100)
            prefix = f"divert {self._port}"
            for idx, r in enumerate(rules):
                rule_num = base_rule_num + idx
                # ipfw add [num] divert [port] [rule...]
                cmd = ["ipfw", "add", str(rule_num)] + prefix.split() + r.split()
                try:
                    subprocess.run(cmd, check=True, capture_output=True)
                    self._applied_rules_with_numbers.append((rule_num, r))
                except (subprocess.CalledProcessError, OSError) as e:  # pragma: no cover
                    self.close()
                    raise RuntimeError(f"Failed to apply ipfw rule: {e}") from e

        self._thread = threading.Thread(target=self._run_loop, name=f"pydivert-bsd-{self._port}", daemon=True)
        self._thread.start()

    def _run_loop(self) -> None:  # noqa: C901
        sock = self._socket
        if not sock:  # pragma: no cover
            return
        while self.is_open and not self._stop_event.is_set():
            try:
                r, _, _ = select.select([sock], [], [], 0.1)
                if not r:
                    continue
                res = sock.recvfrom(65535)
                if not res:
                    continue
                data, addr = res
                if not data:
                    continue
                # addr is (ip_addr, port, flowinfo, scopeid) on FreeBSD for divert sockets.
                # The ip_addr field is INADDR_ANY (0.0.0.0) for outbound packets,
                # and the interface address for inbound packets.
                # The port field encodes the ipfw rule number.
                ip_addr = addr[0] if addr else "0.0.0.0"

                direction = Direction.OUTBOUND if ip_addr == "0.0.0.0" else Direction.INBOUND
                # On loopback, FreeBSD divert socket often gives '0.0.0.0' or '127.0.0.1'
                is_loopback = ip_addr == "0.0.0.0" or ip_addr == "127.0.0.1" or ip_addr == "::1" or not ip_addr

                p = Packet(data, direction=direction, loopback=is_loopback)
                p._bsd_addr = addr

                if p.matches(self._translated_filter):
                    self._queue.put(p)
                    if self._loop and self._async_queue:  # pragma: no cover
                        self._loop.call_soon_threadsafe(self._async_queue.put_nowait, p)
                else:
                    # Packet didn't match our filter, re-inject immediately using the original addr

                    # On FreeBSD loopback, packets often have invalid checksums due to offloading.
                    # We must recalculate them before re-injection, otherwise the stack might drop them.
                    if p.is_loopback and p.ip:
                        p.recalculate_checksums()
                        data = p.raw.tobytes()

                    if isinstance(addr, (list, tuple)) and len(addr) >= 2:
                        send_addr = (str(addr[0]), int(addr[1]))
                    else:
                        send_addr = (str(addr), 0)
                    sock.sendto(data, send_addr)
            except (OSError, ValueError, TypeError) as e:  # pragma: no cover
                if self._stop_event.is_set() or not self.is_open:
                    break
                # Suppress unpacking/value errors during shutdown or mock tests
                logger.error("Error in BSD divert loop: %s", e)
                time.sleep(0.001)

    def close(self) -> None:
        self._stop_event.set()
        if self._socket is not None:
            if sys.platform.startswith("freebsd"):
                for num, _ in self._applied_rules_with_numbers:
                    try:
                        subprocess.run(["ipfw", "delete", str(num)], check=False, capture_output=True)
                    except Exception as e:  # pragma: no cover
                        logger.debug("Failed to delete ipfw rule %d: %s", num, e)
            self._applied_rules_with_numbers = []

            # Unblock the recv loop by closing the socket
            temp_sock = self._socket
            self._socket = None
            if temp_sock:
                temp_sock.close()

        if self in Divert._instances:
            Divert._instances.remove(self)

    @property
    def is_open(self) -> bool:
        return self._socket is not None

    def recv(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = 0.1) -> Packet:
        while self.is_open or not self._queue.empty():
            try:
                return self._queue.get(timeout=timeout)
            except queue.Empty:  # pragma: no cover
                if self._stop_event.is_set():
                    break
                continue
        raise RuntimeError("handle is not open.")  # pragma: no cover

    async def recv_async(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        if not self.is_open:  # pragma: no cover
            raise RuntimeError("handle is not open.")

        if self._async_queue is None:
            self._loop = asyncio.get_running_loop()
            self._async_queue = asyncio.Queue(maxsize=10000)
            try:
                while True:
                    self._async_queue.put_nowait(self._queue.get_nowait())
            except (queue.Empty, asyncio.QueueFull):  # pragma: no cover
                pass

        if timeout is not None:
            return await asyncio.wait_for(self._async_queue.get(), timeout=timeout)
        return await self._async_queue.get()

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        sock = self._socket
        if not sock:
            raise RuntimeError("handle is not open.")

        if recalculate_checksum:
            packet.recalculate_checksums()

        addr = getattr(packet, "_bsd_addr", ("0.0.0.0", 0))
        try:
            raw_bytes = packet.raw.tobytes() if hasattr(packet.raw, "tobytes") else packet.raw

            # On FreeBSD, re-inject using the address info from capture.
            # While divert sockets return a 4-tuple, Python's AF_INET socket.sendto
            # expects a 2-tuple (host, port).
            if isinstance(addr, (list, tuple)) and len(addr) >= 2:
                send_addr = (str(addr[0]), int(addr[1]))
            else:
                send_addr = (str(addr), 0)

            return sock.sendto(raw_bytes, send_addr)
        except Exception as e:  # pragma: no cover
            logger.error(f"Failed to send packet on BSD: {e}")
            raise

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        return self.send(packet, recalculate_checksum)


atexit.register(Divert.cleanup_all)
