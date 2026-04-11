# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import logging
import socket

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pydivert.packet import Packet

# Suppress Scapy warning before it gets imported
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import ICMP, IP, TCP, UDP, ICMPv6EchoRequest, IPv6, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy is not installed")
class TestChecksumFuzzing:

    @settings(max_examples=100)
    @given(
        src=st.integers(min_value=0, max_value=0xffffffff),
        dst=st.integers(min_value=0, max_value=0xffffffff),
        payload=st.binary(min_size=0, max_size=100)
    )
    def test_ipv4_checksum(self, src, dst, payload):
        src_ip = socket.inet_ntoa(src.to_bytes(4, 'big'))
        dst_ip = socket.inet_ntoa(dst.to_bytes(4, 'big'))

        # Create a scapy packet (it calculates the checksum automatically)
        scapy_pkt = IP(src=src_ip, dst=dst_ip) / Raw(load=payload)
        expected_raw = bytes(scapy_pkt)

        # Create a pydivert packet from scapy's raw bytes
        p = Packet(expected_raw)

        # Corrupt the checksum
        p.raw[10:12] = b'\x00\x00'

        # Recalculate
        p.recalculate_checksums()

        # Verify
        assert bytes(p.raw) == expected_raw

    @settings(max_examples=100)
    @given(
        src=st.integers(min_value=0, max_value=0xffffffff),
        dst=st.integers(min_value=0, max_value=0xffffffff),
        src_port=st.integers(min_value=0, max_value=65535),
        dst_port=st.integers(min_value=0, max_value=65535),
        payload=st.binary(min_size=0, max_size=100)
    )
    def test_tcp_ipv4_checksum(self, src, dst, src_port, dst_port, payload):
        src_ip = socket.inet_ntoa(src.to_bytes(4, 'big'))
        dst_ip = socket.inet_ntoa(dst.to_bytes(4, 'big'))

        scapy_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port) / Raw(load=payload)
        expected_raw = bytes(scapy_pkt)

        p = Packet(expected_raw)
        # Corrupt IP and TCP checksums
        p.raw[10:12] = b'\x00\x00'
        p.raw[36:38] = b'\x00\x00'

        p.recalculate_checksums()
        assert bytes(p.raw) == expected_raw

    @settings(max_examples=100)
    @given(
        src=st.integers(min_value=0, max_value=0xffffffff),
        dst=st.integers(min_value=0, max_value=0xffffffff),
        src_port=st.integers(min_value=0, max_value=65535),
        dst_port=st.integers(min_value=0, max_value=65535),
        payload=st.binary(min_size=0, max_size=100)
    )
    def test_udp_ipv4_checksum(self, src, dst, src_port, dst_port, payload):
        src_ip = socket.inet_ntoa(src.to_bytes(4, 'big'))
        dst_ip = socket.inet_ntoa(dst.to_bytes(4, 'big'))

        scapy_pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=payload)
        expected_raw = bytes(scapy_pkt)

        p = Packet(expected_raw)
        # Corrupt IP and UDP checksums
        p.raw[10:12] = b'\x00\x00'
        p.raw[26:28] = b'\x00\x00'

        p.recalculate_checksums()
        assert bytes(p.raw) == expected_raw

    @settings(max_examples=100)
    @given(
        src=st.integers(min_value=0, max_value=0xffffffff),
        dst=st.integers(min_value=0, max_value=0xffffffff),
        payload=st.binary(min_size=0, max_size=100)
    )
    def test_icmp_ipv4_checksum(self, src, dst, payload):
        src_ip = socket.inet_ntoa(src.to_bytes(4, 'big'))
        dst_ip = socket.inet_ntoa(dst.to_bytes(4, 'big'))

        scapy_pkt = IP(src=src_ip, dst=dst_ip) / ICMP() / Raw(load=payload)
        expected_raw = bytes(scapy_pkt)

        p = Packet(expected_raw)
        # Corrupt IP and ICMP checksums
        p.raw[10:12] = b'\x00\x00'
        p.raw[22:24] = b'\x00\x00'

        p.recalculate_checksums()
        assert bytes(p.raw) == expected_raw

    @settings(max_examples=50)
    @given(
        src_port=st.integers(min_value=0, max_value=65535),
        dst_port=st.integers(min_value=0, max_value=65535),
        payload=st.binary(min_size=0, max_size=100)
    )
    def test_tcp_ipv6_checksum(self, src_port, dst_port, payload):
        scapy_pkt = IPv6(src="::1", dst="::1") / TCP(sport=src_port, dport=dst_port) / Raw(load=payload)
        expected_raw = bytes(scapy_pkt)

        p = Packet(expected_raw)
        p.raw[56:58] = b'\x00\x00' # TCP checksum in IPv6

        p.recalculate_checksums()
        assert bytes(p.raw) == expected_raw

    @settings(max_examples=50)
    @given(
        payload=st.binary(min_size=0, max_size=100)
    )
    def test_icmpv6_checksum(self, payload):
        scapy_pkt = IPv6(src="::1", dst="::1") / ICMPv6EchoRequest() / Raw(load=payload)
        expected_raw = bytes(scapy_pkt)

        p = Packet(expected_raw)
        p.raw[42:44] = b'\x00\x00' # ICMPv6 checksum

        p.recalculate_checksums()
        assert bytes(p.raw) == expected_raw
