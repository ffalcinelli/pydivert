# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import logging
import queue
import threading
import socket
import asyncio
import subprocess
import re
import atexit
from pydivert.base import BaseDivert
from pydivert.packet import Packet
from pydivert.consts import Layer, Flag

logger = logging.getLogger(__name__)

try:
    from netfilterqueue import NetfilterQueue as NFQ
except ImportError:
    NFQ = None

class NetFilterQueue(BaseDivert):
    """
    Linux implementation using NetFilterQueue and iptables.
    """
    _instances = set()

    def __init__(self, filter: str = "true", layer: Layer = Layer.NETWORK, priority: int = 0, flags: Flag = Flag.DEFAULT) -> None:
        super().__init__(filter, layer, priority, flags)
        self._nfqueue = None
        self._queue_num = 0 if priority == 0 else priority # Use priority as queue number if specified
        self._queue = queue.Queue(maxsize=10000)
        self._thread = None
        self._translated_filter = self.filter
        self._applied_rules = []
        NetFilterQueue._instances.add(self)

    @classmethod
    def _cleanup_all(cls):
        for instance in list(cls._instances):
            instance.close()

    def _parse_filter_to_iptables(self):
        rules = []
        filter_str = self._translated_filter
        if filter_str.lower() == "true":
            # If true, we could intercept everything, but that breaks SSH in Vagrant.
            # So we don't intercept everything blindly.
            return []
        elif filter_str.lower() == "tcp":
            rules.append(["-p", "tcp"])
        elif filter_str.lower() == "udp":
            rules.append(["-p", "udp"])
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
                        rules.append(["-p", proto, "--dport", port])
                    else:
                        rules.append(["-p", proto, "--sport", port])
        return rules

    def open(self) -> None:
        if NFQ is None:
            raise ImportError("netfilterqueue library not found. Install it with 'pip install NetFilterQueue'.")
        logger.info("Opening NetFilterQueue %d with filter: %s", self._queue_num, self._translated_filter)
        
        self._applied_rules = self._parse_filter_to_iptables()
        for r in self._applied_rules:
            try:
                subprocess.run(["iptables", "-I", "INPUT"] + r + ["-j", "NFQUEUE", "--queue-num", str(self._queue_num)], check=True)
                subprocess.run(["iptables", "-I", "OUTPUT"] + r + ["-j", "NFQUEUE", "--queue-num", str(self._queue_num)], check=True)
            except Exception as e:
                logger.error(f"Failed to add iptables rule: {e}")

        self._nfqueue = NFQ()
        try:
            self._nfqueue.bind(self._queue_num, self._callback)
        except OSError as e:
            self._nfqueue = None
            self._remove_rules()
            raise OSError(f"Failed to bind to NFQueue {self._queue_num}: {e}. Are you root?")

        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _remove_rules(self):
        for r in self._applied_rules:
            try:
                subprocess.run(["iptables", "-D", "INPUT"] + r + ["-j", "NFQUEUE", "--queue-num", str(self._queue_num)], check=False, stderr=subprocess.DEVNULL)
                subprocess.run(["iptables", "-D", "OUTPUT"] + r + ["-j", "NFQUEUE", "--queue-num", str(self._queue_num)], check=False, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        self._applied_rules = []

    def _run_loop(self):
        try:
            self._nfqueue.run()
        except Exception as e:
            logger.error(f"NFQueue loop error: {e}")

    def _callback(self, pkt):
        raw = pkt.get_payload()
        p = Packet(raw)
        
        # User space filtering
        if p.matches(self._translated_filter):
            p._nfq_pkt = pkt
            try:
                self._queue.put(p, block=False)
            except queue.Full:
                logger.warning("Packet queue full, dropping intercepted packet to prevent OOM")
                pkt.accept()
        else:
            pkt.accept()

    def close(self) -> None:
        if self._nfqueue:
            logger.info("Closing NetFilterQueue")
            try:
                self._nfqueue.unbind()
            except Exception:
                pass
            self._nfqueue = None
        if self._thread:
            self._thread = None
        self._remove_rules()
        if self in NetFilterQueue._instances:
            NetFilterQueue._instances.remove(self)

    @property
    def is_open(self) -> bool:
        return self._nfqueue is not None

    def recv(self) -> Packet:
        if not self.is_open:
            raise RuntimeError("Queue is not open.")
        return self._queue.get()

    async def recv_async(self) -> Packet:
        if not self.is_open:
            raise RuntimeError("Queue is not open.")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._queue.get)

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        if not self.is_open:
            raise RuntimeError("Queue is not open.")
        
        if recalculate_checksum:
            packet.recalculate_checksums()

        nfq_pkt = getattr(packet, '_nfq_pkt', None)
        if nfq_pkt:
            raw = packet.raw.tobytes() if hasattr(packet.raw, "tobytes") else packet.raw
            nfq_pkt.set_payload(raw)
            nfq_pkt.accept()
        else:
            # Inject new packet using raw socket
            try:
                if packet.ipv4:
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
