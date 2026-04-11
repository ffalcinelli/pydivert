# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from __future__ import annotations

import asyncio
import atexit
import logging
import re
import socket
import subprocess

from pydivert.base import BaseDivert
from pydivert.consts import Direction, Flag, Layer
from pydivert.packet import Packet

logger = logging.getLogger(__name__)

class MacOSDivert(BaseDivert):
    """
    macOS implementation of the Divert interface using **Divert Sockets** and **pf**.

    This implementation targets macOS systems using the `pf` firewall.
    It uses anchors to avoid modifying the main `/etc/pf.conf` directly.

    **Requirements:**
    - Root privileges to modify `pf` rules and open raw sockets.
    - macOS with `pf` enabled (the implementation will try to enable it).

    **How it works:**
    1.  On `.open()`, it translates the WinDivert-style `filter` to `pf` rules.
    2.  It creates a `pf` anchor (typically under `com.apple/pydivert.<port>`).
    3.  It opens a raw `IPPROTO_DIVERT` socket bound to a specific port.
    4.  `pf` redirects packets matching the rules to the divert socket.
    5.  `.recv()` reads raw IP packets from the socket.
    6.  `.send()` writes raw packets back to the divert socket.
    7.  `.close()` flushes the anchor and closes the socket.

    **Limitations:**
    - Only supports `Layer.NETWORK`.
    - Only supports IPv4 (limitation of macOS `pf` divert sockets).
    - Advanced WinDivert features (Flow/Socket/Reflect) are not supported.
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
        self._is_pf_enabled_by_us = False
        MacOSDivert._instances.add(self)

    @classmethod
    def _cleanup_all(cls):
        for instance in list(cls._instances):
            instance.close()

    def _parse_filter_to_pf(self):
        """
        Translates a WinDivert filter string into macOS PF (packet filter) rules.
        """
        filter_str = self.filter.strip()
        directions = self._get_pf_directions(filter_str)
        proto, pf_from, pf_to = self._get_pf_components(filter_str)
        pf_extra = " on lo0" if re.search(r'\bloopback\b', filter_str, re.I) else ""

        rules = []
        for direction in directions:
            rule = f"pass {direction} quick proto {proto} from {pf_from} to {pf_to} {pf_extra} divert {self._port}"
            # Clean up double spaces
            rule = re.sub(r'\s+', ' ', rule).strip()
            rules.append(rule)
        return rules

    def _get_pf_directions(self, filter_str):
        inbound = re.search(r'\binbound\b', filter_str, re.I)
        outbound = re.search(r'\boutbound\b', filter_str, re.I)
        if inbound and not outbound:
            return ["in"]
        if outbound and not inbound:
            return ["out"]
        return ["in", "out"]

    def _get_pf_components(self, filter_str):
        clean_filter = re.sub(r'\b(inbound|outbound|and|or)\b', ' ', filter_str, flags=re.IGNORECASE).strip()
        clean_filter = re.sub(r'\s+', ' ', clean_filter)

        proto = "ip"
        if re.search(r'\btcp\b', clean_filter, re.I):
            proto = "tcp"
        elif re.search(r'\budp\b', clean_filter, re.I):
            proto = "udp"
        elif re.search(r'\bicmp\b', clean_filter, re.I):
            proto = "icmp"

        pf_from = "any"
        src_match = re.search(r'ip\.SrcAddr\s*==\s*["\']?([\d\.]+)["\']?', filter_str, re.I)
        if src_match:
            pf_from = src_match.group(1)

        pf_to = "any"
        dst_match = re.search(r'ip\.DstAddr\s*==\s*["\']?([\d\.]+)["\']?', filter_str, re.I)
        if dst_match:
            pf_to = dst_match.group(1)

        m = re.search(r'(tcp|udp)\.(DstPort|SrcPort)\s*==\s*(\d+)', filter_str, flags=re.IGNORECASE)
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

    def close(self) -> None:
        if self._socket:
            logger.info("Closing macOS divert socket on port %d", self._port)
            self._socket.close()
            self._socket = None

        # Clean up PF anchor
        try:
            subprocess.run(["pfctl", "-a", self._anchor_name, "-F", "all"], check=False, capture_output=True)
            # We don't necessarily want to disable PF if we enabled it, as other apps might be using it now.
            # But according to some practices, if we enabled it, we should disable it if no other anchors are active.
            # However, for pydivert, we just leave it be or follow the user's preference.
            # To keep it simple and safe, we don't disable PF unless specifically requested.
        except Exception:
            pass

        if self in MacOSDivert._instances:
            MacOSDivert._instances.remove(self)

    @property
    def is_open(self) -> bool:
        return self._socket is not None

    def recv(self) -> Packet:
        if self._socket is None:
            raise RuntimeError("Socket is not open.")

        while True:
            try:
                data, addr = self._socket.recvfrom(65535)
            except OSError as e:
                if self._socket is None:
                    raise RuntimeError("Socket closed during recv") from e
                raise e

            # For divert sockets:
            # - If the packet was outbound, addr[0] is "0.0.0.0"
            # - If the packet was inbound, addr[0] is the interface's IP address
            direction = Direction.OUTBOUND if addr[0] == "0.0.0.0" else Direction.INBOUND

            p = Packet(data, direction=direction)
            p._bsd_addr = addr

            # User space filtering if needed (e.g. for v6 or complex filters)
            if p.matches(self.filter):
                return p
            else:
                try:
                    self.send(p, recalculate_checksum=False)
                except Exception:
                    pass

    async def recv_async(self) -> Packet:
        if not self.is_open:
            raise RuntimeError("Socket is not open.")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.recv)

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        if self._socket is None:
            raise RuntimeError("Socket is not open.")

        if recalculate_checksum:
            packet.recalculate_checksums()

        addr = getattr(packet, '_bsd_addr', (packet.dst_addr, 0))
        try:
            return self._socket.sendto(packet.raw, addr)
        except Exception as e:
            logger.error(f"Failed to send packet: {e}")
            return 0

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        return self.send(packet, recalculate_checksum)

atexit.register(MacOSDivert._cleanup_all)
