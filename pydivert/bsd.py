# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import logging
import socket
import asyncio
import subprocess
import sys
import re
import atexit
from pydivert.base import BaseDivert
from pydivert.packet import Packet
from pydivert.consts import Layer, Flag

logger = logging.getLogger(__name__)

class Divert(BaseDivert):
    """
    BSD implementation using divert sockets.
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
        if filter_str.lower() == "true":
            rules.append(f"divert {self._port} ip from any to any")
        elif filter_str.lower() == "tcp":
            rules.append(f"divert {self._port} tcp from any to any")
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
                        # Also need the return path if loopback or stateful?
                    else:
                        rules.append(f"divert {self._port} {proto} from any {port} to any")
        return rules

    def open(self) -> None:
        logger.info("Opening BSD divert socket on port %d with filter: %s", self._port, self._translated_filter)
        try:
            # IPPROTO_DIVERT isn't in all Python versions' socket module by name
            IPPROTO_DIVERT = getattr(socket, 'IPPROTO_DIVERT', 258) 
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_DIVERT)
            self._socket.bind(('0.0.0.0', self._port))
        except (OSError, PermissionError) as e:
            self._socket = None
            raise OSError(f"Failed to open divert socket on port {self._port}: {e}. Are you root?")

        if sys.platform.startswith("freebsd"):
            self._applied_rules = self._parse_filter_to_ipfw()
            for r in self._applied_rules:
                try:
                    subprocess.run(["ipfw", "add", "100", *r.split()], check=True)
                except Exception as e:
                    logger.error(f"Failed to apply ipfw rule: {e}")

    def close(self) -> None:
        if self._socket:
            logger.info("Closing BSD divert socket")
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
        
        if sys.platform.startswith("freebsd"):
            for r in self._applied_rules:
                try:
                    # Very crude way to delete rules
                    subprocess.run(["ipfw", "delete", "100"], check=False, stderr=subprocess.DEVNULL)
                except Exception:
                    pass
        self._applied_rules = []
        if self in Divert._instances:
            Divert._instances.remove(self)

    @property
    def is_open(self) -> bool:
        return self._socket is not None

    def recv(self) -> Packet:
        if not self.is_open:
            raise RuntimeError("Socket is not open.")
        
        while True:
            data, addr = self._socket.recvfrom(65535)
            p = Packet(data)
            p._bsd_addr = addr # Store original addr for re-injection
            
            # User space filtering
            if p.matches(self._translated_filter):
                return p
            else:
                # If it doesn't match, we must re-inject it so we don't break traffic!
                self._socket.sendto(data, addr)

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
        raw_bytes = packet.raw.tobytes() if hasattr(packet.raw, "tobytes") else packet.raw
        return self._socket.sendto(raw_bytes, addr)

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        return self.send(packet, recalculate_checksum)

atexit.register(Divert._cleanup_all)
