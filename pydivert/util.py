# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import re
import socket
import struct

from pydivert.consts import CalcChecksumsOption


def fromhex(x: str) -> bytes:
    """Convert a hex string to bytes, ignoring spaces and colons."""
    return bytes.fromhex(x.replace(" ", "").replace(":", ""))

def raw_property(fmt: str, offset: int, docs: str | None = None):
    """Create a property that unpacks/packs a value from the raw packet at the given offset."""
    def getter(self):
        return struct.unpack_from(fmt, self.raw, offset)[0]

    def setter(self, val):
        struct.pack_into(fmt, self.raw, offset, val)

    return property(getter, setter, doc=docs)

def flag_property(name: str, offset: int, bit: int, docs: str | None = None):
    """Create a property that gets/sets a bit flag in the raw packet at the given offset."""
    def getter(self):
        return bool(self.raw[offset] & bit)

    def setter(self, val):
        if val:
            self.raw[offset] |= bit
        else:
            self.raw[offset] &= ~bit

    return property(getter, setter, doc=docs)

def calc_csum(data: bytes) -> int:
    """Calculate the internet checksum for the given data."""
    if len(data) % 2 == 1:
        data += b'\0'
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

def fallback_recalculate_checksums(packet, flags: int = 0) -> int:
    """Non-Windows fallback for checksum recalculation."""
    count = 0
    ipproto, proto_start = packet.protocol

    if packet.ipv4:
        if not (flags & CalcChecksumsOption.NO_IP_CHECKSUM):
            ip_hdr = bytearray(packet.ipv4.raw[:packet.ipv4.header_len])
            ip_hdr[10:12] = b'\x00\x00'
            csum = calc_csum(ip_hdr)
            struct.pack_into("!H", packet.raw, packet.ipv4._start + 10, csum)
            count += 1

        pseudo_hdr = struct.pack("!4s4sBBH",
            socket.inet_aton(packet.ipv4.src_addr),
            socket.inet_aton(packet.ipv4.dst_addr),
            0, ipproto or 0, len(packet.raw) - (proto_start or 0))
    elif packet.ipv6:
        pseudo_hdr = struct.pack("!16s16sI3xB",
            socket.inet_pton(socket.AF_INET6, packet.ipv6.src_addr),
            socket.inet_pton(socket.AF_INET6, packet.ipv6.dst_addr),
            len(packet.raw) - (proto_start or 0),
            ipproto or 0)
    else:
        return 0

    if proto_start is not None:
        count += _recalc_proto_checksums(packet, pseudo_hdr, proto_start, flags)

    return count

def _recalc_proto_checksums(packet, pseudo_hdr, proto_start, flags):
    count = 0
    if packet.tcp:
        if not (flags & CalcChecksumsOption.NO_TCP_CHECKSUM):
            tcp_hdr_payload = bytearray(packet.tcp.raw)
            tcp_hdr_payload[16:18] = b'\x00\x00'
            csum = calc_csum(pseudo_hdr + tcp_hdr_payload)
            struct.pack_into("!H", packet.raw, proto_start + 16, csum)
            count += 1
    elif packet.udp:
        if not (flags & CalcChecksumsOption.NO_UDP_CHECKSUM):
            udp_hdr_payload = bytearray(packet.udp.raw)
            udp_hdr_payload[6:8] = b'\x00\x00'
            csum = calc_csum(pseudo_hdr + udp_hdr_payload)
            if csum == 0:
                csum = 0xFFFF
            struct.pack_into("!H", packet.raw, proto_start + 6, csum)
            count += 1
    elif packet.icmpv4:
        if not (flags & CalcChecksumsOption.NO_ICMP_CHECKSUM):
            icmp_hdr_payload = bytearray(packet.icmpv4.raw)
            icmp_hdr_payload[2:4] = b'\x00\x00'
            csum = calc_csum(icmp_hdr_payload)
            struct.pack_into("!H", packet.raw, proto_start + 2, csum)
            count += 1
    elif packet.icmpv6:
        if not (flags & CalcChecksumsOption.NO_ICMPV6_CHECKSUM):
            icmp_hdr_payload = bytearray(packet.icmpv6.raw)
            icmp_hdr_payload[2:4] = b'\x00\x00'
            csum = calc_csum(pseudo_hdr + icmp_hdr_payload)
            struct.pack_into("!H", packet.raw, proto_start + 2, csum)
            count += 1
    return count

def fallback_matches(packet, filter: str) -> bool:
    """Non-Windows fallback for filter evaluation."""
    filter_lower = filter.lower()
    if filter_lower == "true":
        return True
    if filter_lower == "false":
        return False

    # Simple eval logic for tests
    py_filter = re.sub(r'\b(or)\b', ' or ', filter_lower)
    py_filter = re.sub(r'\b(and)\b', ' and ', py_filter)
    py_filter = py_filter.replace('||', ' or ').replace('&&', ' and ')

    mapping = {
        'tcp.dstport': str(packet.dst_port) if packet.tcp else 'None',
        'tcp.srcport': str(packet.src_port) if packet.tcp else 'None',
        'udp.dstport': str(packet.dst_port) if packet.udp else 'None',
        'udp.srcport': str(packet.src_port) if packet.udp else 'None',
        'ip.dstaddr': f"'{packet.dst_addr}'",
        'ip.srcaddr': f"'{packet.src_addr}'",
        'tcp': 'True' if packet.tcp else 'False',
        'udp': 'True' if packet.udp else 'False',
        'icmp': 'True' if packet.icmp else 'False',
        'ipv4': 'True' if packet.ipv4 else 'False',
        'ipv6': 'True' if packet.ipv6 else 'False',
        'outbound': 'True' if packet.is_outbound else 'False',
        'inbound': 'True' if packet.is_inbound else 'False',
        'loopback': 'True' if packet.is_loopback else 'False'
    }

    for k, v in mapping.items():
        py_filter = py_filter.replace(k, v)

    try:
        return bool(eval(py_filter, {"__builtins__": {}}))
    except Exception:
        return True
