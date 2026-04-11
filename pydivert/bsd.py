# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import asyncio
import atexit
import logging
import re
import socket
import subprocess
import sys

from pydivert.base import BaseDivert
from pydivert.consts import Flag, Layer
from pydivert.packet import Packet

logger = logging.getLogger(__name__)

class Divert(BaseDivert):
    """
    BSD implementation of the Divert interface using **Divert Sockets** and **ipfw**.

    This implementation targets FreeBSD and macOS systems that support `IPPROTO_DIVERT`
    sockets and the `ipfw` firewall.

    **Requirements:**
    - FreeBSD with a kernel compiled with `IPFW` and `IPDIVERT` support.
    - macOS (Intel-based, SIP might need to be disabled for some operations).
    - Root privileges to modify `ipfw` rules and open raw sockets.

    **How it works:**
    1.  On FreeBSD, `.open()` translates the WinDivert-style `filter` to `ipfw divert` rules.
    2.  It opens a raw `IPPROTO_DIVERT` socket bound to a specific port (derived from `priority`).
    3.  FreeBSD redirects packets matching the `ipfw` rules to the divert socket.
    4.  `.recv()` reads raw IP packets from the socket.
    5.  `.send()` writes raw packets back to the divert socket, which are then re-injected
        into the networking stack after the rule that diverted them.
    6.  `.close()` removes the `ipfw` rules and closes the socket.

    **Limitations:**
    - This implementation is less feature-rich than WinDivert (no Flow/Socket/Reflect layers).
    - It only supports `Layer.NETWORK`.
    - macOS support for divert sockets is largely deprecated in newer versions.
    """
    _instances = set()

    def __init__(self, filter: str = "true", layer: Layer = Layer.NETWORK, priority: int = 0, flags: Flag = Flag.DEFAULT) -> None:
        super().__init__(filter, layer, priority, flags)
        self._socket = None
        self._port = 8888 + (priority % 1000)
        self._translated_filter = self.filter
        self._applied_rules = []
        Divert._instances.add(self)

    @classmethod
    def _cleanup_all(cls):
        for instance in list(cls._instances):
            instance.close()

    def _parse_filter_to_ipfw(self):
        rules = []
        filter_str = self._translated_filter

        # Base rule for broad interception
        if filter_str.lower() == "true":
            # Avoid port 22 (SSH)
            rules.append(f"divert {self._port} ip from any to any not port 22")
        elif filter_str.lower() == "tcp":
            rules.append(f"divert {self._port} tcp from any to any not port 22")
        elif filter_str.lower() == "udp":
            rules.append(f"divert {self._port} udp from any to any")
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
                        rules.append(f"divert {self._port} {proto} from any to any {port}")
                    else:
                        rules.append(f"divert {self._port} {proto} from any {port} to any")
                elif part.lower() == "loopback":
                    rules.append(f"divert {self._port} ip from any to any via lo0")
                elif part.lower() == "outbound":
                    rules.append(f"divert {self._port} ip from any to any out")
        return rules

    def open(self) -> None:
        logger.info("Opening BSD divert socket on port %d with filter: %s", self._port, self._translated_filter)

        # IPPROTO_DIVERT isn't in all Python versions' socket module by name
        IPPROTO_DIVERT = getattr(socket, 'IPPROTO_DIVERT', 258)

        # Try a few ports if busy
        for _i in range(10):
            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_DIVERT)
                self._socket.bind(('0.0.0.0', self._port))
                break
            except (OSError, PermissionError) as e:
                if getattr(e, 'errno', None) == 48 or "Address already in use" in str(e):
                    self._port += 1
                    continue
                self._socket = None
                raise OSError(f"Failed to open divert socket on port {self._port}: {e}. Are you root?")
        else:
             raise OSError("Failed to find a free port for divert socket. Are you root?")

        if sys.platform.startswith("freebsd"):
            self._applied_rules = self._parse_filter_to_ipfw()
            self._applied_rules_with_numbers = []
            for r in self._applied_rules:
                try:
                    # Use a range of rules to avoid overlap in parallel tests
                    rule_num = 100 + (self._port % 1000)
                    subprocess.run(["ipfw", "add", str(rule_num), *r.split()], check=True, capture_output=True)
                    self._applied_rules_with_numbers.append((rule_num, r))
                except Exception as e:
                    logger.error(f"Failed to apply ipfw rule: {e}")

    def close(self) -> None:
        if self._socket:
            logger.info("Closing BSD divert socket on port %d", self._port)
            if sys.platform.startswith("freebsd"):
                if hasattr(self, '_applied_rules_with_numbers'):
                    for num, _r in self._applied_rules_with_numbers:
                        try:
                            subprocess.run(["ipfw", "delete", str(num)], check=False, capture_output=True)
                        except Exception:
                            pass
            self._socket.close()
            self._socket = None

        if self in Divert._instances:
            Divert._instances.remove(self)
        self._applied_rules = []

    @property
    def is_open(self) -> bool:
        return self._socket is not None

    def recv(self) -> Packet:
        if not self.is_open:
            raise RuntimeError("Socket is not open.")

        while True:
            try:
                data, addr = self._socket.recvfrom(65535)
            except OSError as e:
                if not self.is_open:
                    raise RuntimeError("Socket closed during recv")
                raise e

            p = Packet(data)
            p._bsd_addr = addr

            # User space filtering
            if p.matches(self._translated_filter):
                return p
            else:
                try:
                    self._socket.sendto(data, addr)
                except Exception:
                    pass

    async def recv_async(self) -> Packet:
        if not self.is_open:
            raise RuntimeError("Socket is not open.")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.recv)

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        if not self.is_open:
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

atexit.register(Divert._cleanup_all)
