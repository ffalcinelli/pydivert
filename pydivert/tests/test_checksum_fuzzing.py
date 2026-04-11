# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import socket

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pydivert.packet import Packet

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

        # Check if it matches scapy's ground truth
        assert p.raw.tobytes() == expected_raw

    @settings(max_examples=100)
    @given(
        src_ip=st.integers(min_value=0, max_value=0xffffffff),
        dst_ip=st.integers(min_value=0, max_value=0xffffffff),
        src_port=st.integers(min_value=0, max_value=65535),
        dst_port=st.integers(min_value=0, max_value=65535),
        payload=st.binary(min_size=0, max_size=100)
    )
    def test_tcp_ipv4_checksum(self, src_ip, dst_ip, src_port, dst_port, payload):
        src_ip_str = socket.inet_ntoa(src_ip.to_bytes(4, 'big'))
        dst_ip_str = socket.inet_ntoa(dst_ip.to_bytes(4, 'big'))

        scapy_pkt = IP(src=src_ip_str, dst=dst_ip_str) / TCP(sport=src_port, dport=dst_port) / Raw(load=payload)
        expected_raw = bytes(scapy_pkt)

        p = Packet(expected_raw)

        # Corrupt IP and TCP checksums
        p.raw[10:12] = b'\x00\x00' # IP
        tcp_start = (p.raw[0] & 0x0F) * 4
        p.raw[tcp_start + 16 : tcp_start + 18] = b'\x00\x00' # TCP

        p.recalculate_checksums()

        assert p.raw.tobytes() == expected_raw

    @settings(max_examples=100)
    @given(
        src_ip=st.integers(min_value=0, max_value=0xffffffff),
        dst_ip=st.integers(min_value=0, max_value=0xffffffff),
        src_port=st.integers(min_value=0, max_value=65535),
        dst_port=st.integers(min_value=0, max_value=65535),
        payload=st.binary(min_size=0, max_size=100)
    )
    def test_udp_ipv4_checksum(self, src_ip, dst_ip, src_port, dst_port, payload):
        src_ip_str = socket.inet_ntoa(src_ip.to_bytes(4, 'big'))
        dst_ip_str = socket.inet_ntoa(dst_ip.to_bytes(4, 'big'))

        scapy_pkt = IP(src=src_ip_str, dst=dst_ip_str) / UDP(sport=src_port, dport=dst_port) / Raw(load=payload)
        expected_raw = bytes(scapy_pkt)

        p = Packet(expected_raw)

        # Corrupt IP and UDP checksums
        p.raw[10:12] = b'\x00\x00' # IP
        udp_start = (p.raw[0] & 0x0F) * 4
        p.raw[udp_start + 6 : udp_start + 8] = b'\x00\x00' # UDP

        p.recalculate_checksums()

        assert p.raw.tobytes() == expected_raw

    @settings(max_examples=100)
    @given(
        src_ip=st.integers(min_value=0, max_value=0xffffffff),
        dst_ip=st.integers(min_value=0, max_value=0xffffffff),
        payload=st.binary(min_size=0, max_size=100)
    )
    def test_icmp_ipv4_checksum(self, src_ip, dst_ip, payload):
        src_ip_str = socket.inet_ntoa(src_ip.to_bytes(4, 'big'))
        dst_ip_str = socket.inet_ntoa(dst_ip.to_bytes(4, 'big'))

        scapy_pkt = IP(src=src_ip_str, dst=dst_ip_str) / ICMP() / Raw(load=payload)
        expected_raw = bytes(scapy_pkt)

        p = Packet(expected_raw)

        # Corrupt ICMP checksum
        icmp_start = (p.raw[0] & 0x0F) * 4
        p.raw[icmp_start + 2 : icmp_start + 4] = b'\x00\x00'

        p.recalculate_checksums()
        assert p.raw.tobytes() == expected_raw

    @settings(max_examples=100)
    @given(
        payload=st.binary(min_size=0, max_size=100)
    )
    def test_tcp_ipv6_checksum(self, payload):
        scapy_pkt = IPv6(src="::1", dst="::1") / TCP() / Raw(load=payload)
        expected_raw = bytes(scapy_pkt)

        p = Packet(expected_raw)

        # Corrupt TCP checksum
        tcp_start = 40 # Standard IPv6
        p.raw[tcp_start + 16 : tcp_start + 18] = b'\x00\x00'

        p.recalculate_checksums()
        assert p.raw.tobytes() == expected_raw

    @settings(max_examples=100)
    @given(
        payload=st.binary(min_size=0, max_size=100)
    )
    def test_icmpv6_checksum(self, payload):
        scapy_pkt = IPv6(src="::1", dst="::1") / ICMPv6EchoRequest() / Raw(load=payload)
        expected_raw = bytes(scapy_pkt)

        p = Packet(expected_raw)

        # Corrupt ICMPv6 checksum
        icmp_start = 40 # Standard IPv6
        p.raw[icmp_start + 2 : icmp_start + 4] = b'\x00\x00'

        p.recalculate_checksums()
        assert p.raw.tobytes() == expected_raw
