# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from __future__ import annotations

import logging
import socket
import struct
from typing import TYPE_CHECKING, Any

from pydivert.consts import CalcChecksumsOption

if TYPE_CHECKING:
    from pydivert.packet import Packet

logger = logging.getLogger(__name__)


def fromhex(x: str) -> bytes:
    """Convert a hex string to bytes, ignoring spaces and colons."""
    return bytes.fromhex(x.replace(" ", "").replace(":", ""))


def raw_property(fmt: str, offset: int, docs: str | None = None) -> property:
    """Create a property that unpacks/packs a value from the raw packet at the given offset."""

    def getter(self: Any) -> Any:
        return struct.unpack_from(fmt, self.raw, offset)[0]

    def setter(self, val: Any) -> None:
        struct.pack_into(fmt, self.raw, offset, val)

    return property(getter, setter, doc=docs)


def flag_property(name: str, offset: int, bit: int, docs: str | None = None) -> property:
    """Create a property that gets/sets a bit flag in the raw packet at the given offset."""

    def getter(self: Any) -> bool:
        return bool(self.raw[offset] & bit)

    def setter(self, val: Any) -> None:
        if val:
            self.raw[offset] |= bit
        else:
            self.raw[offset] &= ~bit

    return property(getter, setter, doc=docs)


def calc_csum(data: bytes | bytearray) -> int:
    """Calculate the internet checksum for the given data."""
    if len(data) % 2 == 1:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def fallback_recalculate_checksums(packet: Packet, flags: int = 0) -> int:
    """Non-Windows fallback for checksum recalculation."""
    count = 0
    ipproto, proto_start = packet.protocol

    if packet.ipv4:
        if not (flags & CalcChecksumsOption.NO_IP_CHECKSUM):
            ip_hdr = bytearray(packet.ipv4.raw[: packet.ipv4.header_len])
            ip_hdr[10:12] = b"\x00\x00"
            csum = calc_csum(ip_hdr)
            struct.pack_into("!H", packet.raw, packet.ipv4._start + 10, csum)
            count += 1

        src_addr = packet.ipv4.src_addr
        dst_addr = packet.ipv4.dst_addr
        if src_addr is None or dst_addr is None:
            return 0  # Should not happen with valid IPv4

        pseudo_hdr = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(src_addr),
            socket.inet_aton(dst_addr),
            0,
            ipproto or 0,
            len(packet.raw) - (proto_start or 0),
        )
    elif packet.ipv6:
        src_addr = packet.ipv6.src_addr
        dst_addr = packet.ipv6.dst_addr
        if src_addr is None or dst_addr is None:
            return 0  # Should not happen with valid IPv6

        pseudo_hdr = struct.pack(
            "!16s16sI3xB",
            socket.inet_pton(socket.AF_INET6, src_addr),
            socket.inet_pton(socket.AF_INET6, dst_addr),
            len(packet.raw) - (proto_start or 0),
            ipproto or 0,
        )
    else:
        return 0

    if proto_start is not None:
        count += _recalc_proto_checksums(packet, pseudo_hdr, proto_start, flags)

    return count


def _recalc_proto_checksums(packet: Packet, pseudo_hdr: bytes, proto_start: int, flags: int) -> int:
    count = 0
    if packet.tcp:
        if not (flags & CalcChecksumsOption.NO_TCP_CHECKSUM):
            tcp_hdr_payload = bytearray(packet.tcp.raw)
            tcp_hdr_payload[16:18] = b"\x00\x00"
            csum = calc_csum(pseudo_hdr + tcp_hdr_payload)
            struct.pack_into("!H", packet.raw, proto_start + 16, csum)
            count += 1
    elif packet.udp:
        if not (flags & CalcChecksumsOption.NO_UDP_CHECKSUM):
            udp_hdr_payload = bytearray(packet.udp.raw)
            udp_hdr_payload[6:8] = b"\x00\x00"
            csum = calc_csum(pseudo_hdr + udp_hdr_payload)
            if csum == 0:
                csum = 0xFFFF  # pragma: no cover
            struct.pack_into("!H", packet.raw, proto_start + 6, csum)
            count += 1
    elif packet.icmpv4:
        if not (flags & CalcChecksumsOption.NO_ICMP_CHECKSUM):
            icmp_hdr_payload = bytearray(packet.icmpv4.raw)
            icmp_hdr_payload[2:4] = b"\x00\x00"
            csum = calc_csum(icmp_hdr_payload)
            struct.pack_into("!H", packet.raw, proto_start + 2, csum)
            count += 1
    elif packet.icmpv6:
        if not (flags & CalcChecksumsOption.NO_ICMPV6_CHECKSUM):
            icmp_hdr_payload = bytearray(packet.icmpv6.raw)
            icmp_hdr_payload[2:4] = b"\x00\x00"
            csum = calc_csum(pseudo_hdr + icmp_hdr_payload)
            struct.pack_into("!H", packet.raw, proto_start + 2, csum)
            count += 1
    return count


class AggregateField:
    """Helper for matching aggregate fields like ip.addr or tcp.port."""

    def __init__(self, *values: Any) -> None:
        self.values = values

    def __eq__(self, other: Any) -> bool:
        return any(v == other for v in self.values)

    def __ne__(self, other: Any) -> bool:
        return all(v != other for v in self.values)

    def __gt__(self, other: Any) -> bool:
        return any(v > other for v in self.values)

    def __ge__(self, other: Any) -> bool:
        return any(v >= other for v in self.values)

    def __lt__(self, other: Any) -> bool:
        return any(v < other for v in self.values)

    def __le__(self, other: Any) -> bool:
        return any(v <= other for v in self.values)

    def __bool__(self) -> bool:
        return any(bool(v) for v in self.values)


def fallback_matches(packet: Packet, filter: str) -> bool:
    """Non-Windows fallback for filter evaluation."""
    from pydivert.filter import transpile_to_python

    py_filter = transpile_to_python(filter)

    try:
        return bool(
            eval(py_filter, {"__builtins__": {}, "AggregateField": AggregateField, "packet": packet, "len": len})
        )
    except Exception as e:  # pragma: no cover
        # If eval fails, we return True to be safe (intercept rather than drop)
        logger.debug("Filter evaluation failed for %r: %s", py_filter, e)
        return True
