# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
"""
macOS implementation of the Divert interface using **Divert Sockets**.

.. warning::
   macOS support is currently **experimental**.
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import queue
import re
import socket
import subprocess
import threading
import time
from typing import Any

from pydivert.base import BaseDivert
from pydivert.consts import DEFAULT_PACKET_BUFFER_SIZE, Direction, Flag, Layer
from pydivert.packet import Packet

# Local alias for socket.socket to allow safe patching in tests
_Socket = socket.socket

logger = logging.getLogger(__name__)

# Pre-compiled regular expressions for efficiency
_RE_LOOPBACK = re.compile(r"\bloopback\b", re.IGNORECASE)
_RE_INBOUND = re.compile(r"\binbound\b", re.IGNORECASE)
_RE_OUTBOUND = re.compile(r"\boutbound\b", re.IGNORECASE)
_RE_WHITESPACE = re.compile(r"\s+")
_RE_PF_KEYWORDS = re.compile(r"\b(inbound|outbound|and|or)\b", re.IGNORECASE)
_RE_PROTO_TCP = re.compile(r"\btcp\b", re.IGNORECASE)
_RE_PROTO_UDP = re.compile(r"\budp\b", re.IGNORECASE)
_RE_PROTO_ICMP = re.compile(r"\bicmp\b", re.IGNORECASE)
_RE_SRC_ADDR = re.compile(r'ip\.SrcAddr\s*==\s*["\']?([\d\.]+)["\']?', re.IGNORECASE)
_RE_DST_ADDR = re.compile(r'ip\.DstAddr\s*==\s*["\']?([\d\.]+)["\']?', re.IGNORECASE)
_RE_PORT_MATCH = re.compile(r"(tcp|udp)\.(DstPort|SrcPort)\s*==\s*(\d+)", re.IGNORECASE)


class MacOSDivert(BaseDivert):
    """
    macOS implementation of the Divert interface using **Divert Sockets** and **pf**.

    This backend captures and injects network packets by dynamically interacting with
    the `pf` (Packet Filter) firewall. It sets up an anchor under `com.apple/pydivert`
    and injects `divert-to` rules to route matching traffic to a divert socket.

    **Requirements:**
    - macOS with `pf` enabled.
    - Root privileges to create divert sockets and manipulate the `pf` configuration.

    When the handle is closed, the injected rules and the custom anchor are
    automatically removed.
    """

    _instances: set[MacOSDivert] = set()
    _anchor_base = "com.apple/pydivert"

    def __init__(
        self, filter: str = "true", layer: Layer = Layer.NETWORK, priority: int = 0, flags: Flag = Flag.DEFAULT
    ) -> None:
        super().__init__(filter, layer, priority, flags)
        self._socket: _Socket | None = None
        self._port = 8888 + (priority % 1000)
        self._anchor_name = f"{self._anchor_base}.{self._port}"
        self._queue: queue.Queue[Packet] = queue.Queue(maxsize=10000)
        self._async_queue: asyncio.Queue[Packet] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._is_pf_enabled_by_us = False
        MacOSDivert._instances.add(self)

    @classmethod
    def cleanup_all(cls) -> None:
        for instance in list(cls._instances):
            try:
                instance.close()
            except OSError as e:  # pragma: no cover
                logger.debug("Failed to close MacOSDivert instance: %s", e)

    def _parse_filter_to_pf(self) -> list[str]:
        """
        Translates a WinDivert filter string into macOS PF (packet filter) rules.
        """
        filter_str = self.filter.strip()
        directions = self._get_pf_directions(filter_str)
        proto, pf_from, pf_to = self._get_pf_components(filter_str)
        pf_extra = " on lo0" if _RE_LOOPBACK.search(filter_str) else ""

        rules = []
        for direction in directions:
            rule = (
                f"pass {direction} quick proto {proto} from {pf_from} to {pf_to} "
                f"{pf_extra} divert-packet port {self._port}"
            )
            # Clean up double spaces
            rule = _RE_WHITESPACE.sub(" ", rule).strip()
            rules.append(rule)
        return rules

    def _get_pf_directions(self, filter_str: str) -> list[str]:
        inbound = _RE_INBOUND.search(filter_str)
        outbound = _RE_OUTBOUND.search(filter_str)
        if inbound and not outbound:
            return ["in"]
        if outbound and not inbound:
            return ["out"]  # pragma: no cover
        return ["in", "out"]

    def _get_pf_components(self, filter_str: str) -> tuple[str, str, str]:
        clean_filter = _RE_PF_KEYWORDS.sub(" ", filter_str).strip()
        clean_filter = _RE_WHITESPACE.sub(" ", clean_filter)

        proto = "ip"
        if _RE_PROTO_TCP.search(clean_filter):
            proto = "tcp"
        elif _RE_PROTO_UDP.search(clean_filter):
            proto = "udp"  # pragma: no cover
        elif _RE_PROTO_ICMP.search(clean_filter):
            proto = "icmp"

        pf_from = "any"
        src_match = _RE_SRC_ADDR.search(filter_str)
        if src_match:
            pf_from = src_match.group(1)

        pf_to = "any"
        dst_match = _RE_DST_ADDR.search(filter_str)
        if dst_match:
            pf_to = dst_match.group(1)  # pragma: no cover

        m = _RE_PORT_MATCH.search(filter_str)
        if m:
            proto = m.group(1).lower()
            port_type = m.group(2).lower()
            port = m.group(3)
            if port_type == "dstport":
                pf_to += f" port {port}"
            else:
                pf_from += f" port {port}"  # pragma: no cover

        return proto, pf_from, pf_to

    def open(self) -> None:
        if self.is_open:
            raise RuntimeError("Divert handle is already open.")

        logger.info("Opening macOS divert socket on port %d with filter: %s", self._port, self.filter)

        # 1. Open Socket
        IPPROTO_DIVERT = getattr(socket, "IPPROTO_DIVERT", 258)
        for _i in range(10):
            try:
                self._socket = _Socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_DIVERT)
                self._socket.bind(("0.0.0.0", self._port))
                break
            except (OSError, PermissionError) as e:  # pragma: no cover
                if getattr(e, "errno", None) == 48 or "Address already in use" in str(e):
                    self._port += 1
                    self._anchor_name = f"{self._anchor_base}.{self._port}"
                    continue
                err_msg = f"Failed to open divert socket on port {self._port}: {e}. Are you root?"
                if hasattr(e, "errno") and e.errno is not None:
                    raise OSError(e.errno, err_msg) from e
                raise OSError(err_msg) from e
        else:  # pragma: no cover
            raise OSError("Failed to find a free port for divert socket.")

        # 2. Configure PF
        try:
            # Check if PF is enabled
            res = subprocess.run(["pfctl", "-s", "info"], capture_output=True, text=True)
            if "Status: Disabled" in res.stdout:
                logger.info("Enabling PF...")
                subprocess.run(["pfctl", "-e"], check=True, capture_output=True)
                self._is_pf_enabled_by_us = True

            # Load rules into anchor
            rules = self._parse_filter_to_pf()
            rules_str = "\n".join(rules) + "\n"

            logger.debug("Loading PF rules into anchor %s:\n%s", self._anchor_name, rules_str)

            process = subprocess.Popen(
                ["pfctl", "-a", self._anchor_name, "-f", "-"],
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = process.communicate(input=rules_str)
            if process.returncode != 0:  # pragma: no cover
                raise RuntimeError(f"Failed to load PF rules: {stderr}")

        except (subprocess.SubprocessError, OSError) as e:  # pragma: no cover
            self.close()
            raise RuntimeError(f"Failed to configure PF: {e}") from e

        # 3. Start Capture Thread
        self._thread = threading.Thread(target=self._run_loop, name=f"pydivert-macos-{self._port}", daemon=True)
        self._thread.start()

    def _run_loop(self) -> None:
        sock = self._socket
        if not sock:  # pragma: no cover
            return

        while self.is_open and not self._stop_event.is_set():
            try:
                res = sock.recvfrom(65535)
                if not res:
                    if self._stop_event.is_set():
                        break
                    continue
                data, addr = res
                self._handle_packet(data, addr, sock)
            except (OSError, ValueError, TypeError) as e:  # pragma: no cover
                if self._stop_event.is_set() or not self.is_open:
                    break
                # Suppress errors if we are shutting down or if it's a mock error
                logger.error("Error in macOS divert loop: %s", e)
                if isinstance(e, OSError):
                    break
                time.sleep(0.01)

    def _handle_packet(self, data: bytes, addr: Any, sock: _Socket) -> None:
        if not data:
            return

        # On macOS divert sockets, addr[0] == '0.0.0.0' or '::' often indicates outbound.
        # However, for consistency with BSD and more reliability, we check if the
        # capture address is empty or zeroed.
        is_outbound = not addr or (isinstance(addr, (list, tuple)) and addr and addr[0] in ("0.0.0.0", "::"))
        direction = Direction.OUTBOUND if is_outbound else Direction.INBOUND

        p = Packet(data, direction=direction)
        p._bsd_addr = addr

        if p.matches(self.filter):
            try:
                self._queue.put(p, block=False)
                if self._loop and self._async_queue:  # pragma: no cover
                    try:
                        self._loop.call_soon_threadsafe(self._async_queue.put_nowait, p)
                    except (asyncio.QueueFull, RuntimeError) as e:  # pragma: no cover
                        logger.debug("Failed to put packet in async queue: %s", e)
            except (queue.Full, asyncio.QueueFull):  # pragma: no cover
                logger.warning("MacOSDivert queue full, dropping intercepted packet")
                sock.sendto(data, addr)
        else:
            sock.sendto(data, addr)

    def close(self) -> None:
        self._stop_event.set()
        if self._socket is not None:
            logger.info("Closing macOS divert socket on port %d", self._port)
            # Unblock the recv loop
            temp_sock = self._socket
            self._socket = None  # Mark as closed first
            try:
                temp_sock.close()
            except Exception as e:  # pragma: no cover
                logger.debug("Failed to close macOS divert socket: %s", e)

        # Clean up PF anchor
        try:
            subprocess.run(["pfctl", "-a", self._anchor_name, "-F", "all"], check=False, capture_output=True)
        except Exception as e:  # pragma: no cover
            logger.debug("Failed to clean up PF anchor %s: %s", self._anchor_name, e)

        if self in MacOSDivert._instances:
            MacOSDivert._instances.remove(self)

    @property
    def is_open(self) -> bool:
        return self._socket is not None

    def recv(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = 0.1) -> Packet:
        if not self.is_open and self._queue.empty():
            raise RuntimeError("handle is not open.")
        while not self._stop_event.is_set() or not self._queue.empty():
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
            # Drain sync queue into async queue
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
        if not sock:  # pragma: no cover
            raise RuntimeError("Handle is closed.")

        if recalculate_checksum:
            packet.recalculate_checksums()

        addr = getattr(packet, "_bsd_addr", (packet.dst_addr, 0))
        try:
            raw_bytes = packet.raw.tobytes() if hasattr(packet.raw, "tobytes") else packet.raw
            return sock.sendto(raw_bytes, addr)
        except Exception as e:  # pragma: no cover
            logger.error(f"Failed to send packet on macOS: {e}")
            raise

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        return self.send(packet, recalculate_checksum)


atexit.register(MacOSDivert.cleanup_all)
