# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli

from pydivert.packet import Packet


class PacketBuilder:
    """
    A fluent builder for constructing network packets.
    """

    def __init__(self) -> None:
        self._ip_version = 4
        self._proto = "tcp"
        self._src_addr = "127.0.0.1"
        self._dst_addr = "127.0.0.1"
        self._src_port = 0
        self._dst_port = 0
        self._payload = b""
        self._ttl = 64

    def ipv4(self, src: str = "127.0.0.1", dst: str = "127.0.0.1", ttl: int = 64) -> "PacketBuilder":
        self._ip_version = 4
        self._src_addr = src
        self._dst_addr = dst
        self._ttl = ttl
        return self

    def ipv6(self, src: str = "::1", dst: str = "::1", hop_limit: int = 64) -> "PacketBuilder":
        self._ip_version = 6
        self._src_addr = src
        self._dst_addr = dst
        self._ttl = hop_limit
        return self

    def tcp(self, src_port: int, dst_port: int) -> "PacketBuilder":
        self._proto = "tcp"
        self._src_port = src_port
        self._dst_port = dst_port
        return self

    def udp(self, src_port: int, dst_port: int) -> "PacketBuilder":
        self._proto = "udp"
        self._src_port = src_port
        self._dst_port = dst_port
        return self

    def payload(self, data: bytes) -> "PacketBuilder":
        self._payload = data
        return self

    def build(self) -> Packet:
        # Calculate sizes
        ip_len = 20 if self._ip_version == 4 else 40
        if self._proto == "tcp":
            proto_len = 20
        elif self._proto == "udp":
            proto_len = 8
        else:
            proto_len = 0

        total_len = ip_len + proto_len + len(self._payload)
        raw = bytearray(total_len)

        # Set the protocol, version and header lengths directly in raw before Packet creation!
        if self._ip_version == 4:
            raw[0] = 0x45  # Version 4, IHL 5
            # Total length
            raw[2] = (total_len >> 8) & 0xFF
            raw[3] = total_len & 0xFF
            # Protocol (TCP = 6, UDP = 17)
            raw[9] = 6 if self._proto == "tcp" else 17
        else:
            raw[0] = 0x60  # Version 6
            # Next Header (TCP = 6, UDP = 17)
            raw[6] = 6 if self._proto == "tcp" else 17

        if self._proto == "tcp":
            offset = ip_len
            # Data Offset (5 << 4 = 0x50) in byte 12 of the TCP header
            raw[offset + 12] = 0x50

        # Create basic Packet
        packet = Packet(raw)

        # Set IP fields
        if self._ip_version == 4:
            assert packet.ipv4 is not None
            packet.ipv4.ttl = self._ttl
            packet.ipv4.packet_len = total_len
            packet.src_addr = self._src_addr
            packet.dst_addr = self._dst_addr
        else:
            assert packet.ipv6 is not None
            packet.ipv6.hop_limit = self._ttl
            packet.ipv6.payload_len = proto_len + len(self._payload)
            packet.src_addr = self._src_addr
            packet.dst_addr = self._dst_addr

        # Set Proto fields
        if self._proto == "tcp":
            packet.src_port = self._src_port
            packet.dst_port = self._dst_port
        elif self._proto == "udp":
            packet.src_port = self._src_port
            packet.dst_port = self._dst_port
            assert packet.udp is not None
            packet.udp.payload_len = len(self._payload)

        # Copy payload if present
        if self._payload:
            packet.payload = self._payload

        packet.recalculate_checksums()
        return packet
