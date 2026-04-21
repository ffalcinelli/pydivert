# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
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

from pydivert.base import BaseDivert
from pydivert.consts import Direction, Flag, Layer
from pydivert.packet import Packet

logger = logging.getLogger(__name__)

# Pre-compiled regular expressions for efficiency
_RE_LOOPBACK = re.compile(r'\bloopback\b', re.IGNORECASE)
_RE_INBOUND = re.compile(r'\binbound\b', re.IGNORECASE)
_RE_OUTBOUND = re.compile(r'\boutbound\b', re.IGNORECASE)
_RE_WHITESPACE = re.compile(r'\s+')
_RE_PF_KEYWORDS = re.compile(r'\b(inbound|outbound|and|or)\b', re.IGNORECASE)
_RE_PROTO_TCP = re.compile(r'\btcp\b', re.IGNORECASE)
_RE_PROTO_UDP = re.compile(r'\budp\b', re.IGNORECASE)
_RE_PROTO_ICMP = re.compile(r'\bicmp\b', re.IGNORECASE)
_RE_SRC_ADDR = re.compile(r'ip\.SrcAddr\s*==\s*["\']?([\d\.]+)["\']?', re.IGNORECASE)
_RE_DST_ADDR = re.compile(r'ip\.DstAddr\s*==\s*["\']?([\d\.]+)["\']?', re.IGNORECASE)
_RE_PORT_MATCH = re.compile(r'(tcp|udp)\.(DstPort|SrcPort)\s*==\s*(\d+)', re.IGNORECASE)

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
        self._socket: socket.socket | None = None
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
    def cleanup_all(cls):
        for instance in list(cls._instances):
            try:
                instance.close()
            except Exception:  # pragma: no cover
                pass

    def _parse_filter_to_pf(self):
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
            rule = _RE_WHITESPACE.sub(' ', rule).strip()
            rules.append(rule)
        return rules

    def _get_pf_directions(self, filter_str):
        inbound = _RE_INBOUND.search(filter_str)
        outbound = _RE_OUTBOUND.search(filter_str)
        if inbound and not outbound:
            return ["in"]
        if outbound and not inbound:
            return ["out"]
        return ["in", "out"]

    def _get_pf_components(self, filter_str):
        clean_filter = _RE_PF_KEYWORDS.sub(' ', filter_str).strip()
        clean_filter = _RE_WHITESPACE.sub(' ', clean_filter)

        proto = "ip"
        if _RE_PROTO_TCP.search(clean_filter):
            proto = "tcp"
        elif _RE_PROTO_UDP.search(clean_filter):
            proto = "udp"
        elif _RE_PROTO_ICMP.search(clean_filter):
            proto = "icmp"

        pf_from = "any"
        src_match = _RE_SRC_ADDR.search(filter_str)
        if src_match:
            pf_from = src_match.group(1)

        pf_to = "any"
        dst_match = _RE_DST_ADDR.search(filter_str)
        if dst_match:
            pf_to = dst_match.group(1)

        m = _RE_PORT_MATCH.search(filter_str)
        if m:
            proto = m.group(1).lower()
            port_type = m.group(2).lower()
            port = m.group(3)
            if port_type == 'dstport':
                pf_to += f" port {port}"
            else:
                pf_from += f" port {port}"

        return proto, pf_from, pf_to

    def open(self) -> None:
        if self.is_open:
            raise RuntimeError("Divert handle is already open.")

        logger.info("Opening macOS divert socket on port %d with filter: %s", self._port, self.filter)

        # 1. Open Socket
        IPPROTO_DIVERT = getattr(socket, 'IPPROTO_DIVERT', 258)
        for _i in range(10):
            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_DIVERT)
                self._socket.bind(('0.0.0.0', self._port))
                break
            except (OSError, PermissionError) as e:
                if getattr(e, 'errno', None) == 48 or "Address already in use" in str(e):
                    self._port += 1
                    self._anchor_name = f"{self._anchor_base}.{self._port}"
                    continue
                raise OSError(f"Failed to open divert socket on port {self._port}: {e}. Are you root?") from e
        else:
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
                stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True
            )
            stdout, stderr = process.communicate(input=rules_str)
            if process.returncode != 0:
                raise RuntimeError(f"Failed to load PF rules: {stderr}")

        except Exception as e:
            self.close()
            raise RuntimeError(f"Failed to configure PF: {e}") from e

        # 3. Start Capture Thread
        self._thread = threading.Thread(target=self._run_loop, name=f"pydivert-macos-{self._port}", daemon=True)
        self._thread.start()

    def _run_loop(self):
        sock = self._socket
        if not sock:
            return

        while not self._stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                # On macOS divert sockets, addr[0] == '0.0.0.0' or '::' often indicates outbound.
                # However, for consistency with BSD and more reliability, we check if the
                # capture address is empty or zeroed.
                is_outbound = (not addr or addr[0] == "0.0.0.0" or addr[0] == "::")
                direction = Direction.OUTBOUND if is_outbound else Direction.INBOUND

                p = Packet(data, direction=direction)
                p._bsd_addr = addr

                if p.matches(self.filter):
                    try:
                        self._queue.put(p, block=False)
                        if self._loop and self._async_queue:
                            try:
                                self._loop.call_soon_threadsafe(self._async_queue.put_nowait, p)
                            except Exception:
                                pass
                    except (queue.Full, asyncio.QueueFull):
                        logger.warning("MacOSDivert queue full, dropping intercepted packet")
                        sock.sendto(data, addr)
                else:
                    sock.sendto(data, addr)
            except Exception as e:
                if self._stop_event.is_set():
                    break
                logger.error("Error in macOS divert loop: %s", e)
                if isinstance(e, OSError):
                    raise
                time.sleep(0.01)
    def close(self) -> None:
        self._stop_event.set()
        if self._socket:
            logger.info("Closing macOS divert socket on port %d", self._port)
            # Unblock the recv loop
            temp_sock = self._socket
            self._socket = None
            try:
                temp_sock.close()
            except Exception:
                pass

        # Clean up PF anchor
        try:
            subprocess.run(["pfctl", "-a", self._anchor_name, "-F", "all"], check=False, capture_output=True)
        except Exception:
            pass

        if self in MacOSDivert._instances:
            MacOSDivert._instances.remove(self)

    @property
    def is_open(self) -> bool:
        return self._socket is not None

    def recv(self) -> Packet:
        if not self.is_open:
            raise RuntimeError("Socket is not open.")
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                return self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
        raise RuntimeError("Socket closed during recv")

    async def recv_async(self) -> Packet:
        if not self.is_open:
             raise RuntimeError("Socket is not open.")

        if self._async_queue is None:
            self._loop = asyncio.get_running_loop()
            self._async_queue = asyncio.Queue(maxsize=10000)
            # Drain sync queue into async queue
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

        addr = getattr(packet, '_bsd_addr', (packet.dst_addr, 0))
        try:
            raw_bytes = packet.raw.tobytes() if hasattr(packet.raw, "tobytes") else packet.raw
            return sock.sendto(raw_bytes, addr)
        except Exception as e:
            logger.error(f"Failed to send packet on macOS: {e}")
            raise

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        return self.send(packet, recalculate_checksum)

atexit.register(MacOSDivert.cleanup_all)
