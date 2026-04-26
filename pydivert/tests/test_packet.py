# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import socket
import struct

import pytest

import pydivert
from pydivert import util
from pydivert.consts import Direction, Protocol


def test_ip_modify(packet_factory):
    raw_hex = (
        "45 00 00 28 00 01 00 00 40 06 00 00 7f 00 00 01 7f 00 00 01"
        "00 50 00 50 00 00 00 00 00 00 00 00 50 02 20 00 00 00 00 00"
    )
    x = packet_factory(raw_hex)
    assert x.ipv4 is not None
    assert x.tcp is not None
    assert x.dst_addr == "127.0.0.1"
    x.dst_addr = "8.8.8.8"
    assert x.dst_addr == "8.8.8.8"
    assert x.ipv4.dst_addr == "8.8.8.8"
    assert x.raw.tobytes() == util.fromhex(
        "45 00 00 28 00 01 00 00 40 06 00 00 7f 00 00 01 08 08 08 08"
        "00 50 00 50 00 00 00 00 00 00 00 00 50 02 20 00 00 00 00 00"
    )

    x.dst_addr = "1.2.3.4"
    assert x.dst_addr == "1.2.3.4"
    assert x.raw.tobytes() == util.fromhex(
        "45 00 00 28 00 01 00 00 40 06 00 00 7f 00 00 01 01 02 03 04"
        "00 50 00 50 00 00 00 00 00 00 00 00 50 02 20 00 00 00 00 00"
    )

    # checksum
    a = x.raw.tobytes()
    assert (
        x.recalculate_checksums(
            pydivert.CalcChecksumsOption.NO_IP_CHECKSUM | pydivert.CalcChecksumsOption.NO_TCP_CHECKSUM
        )
        >= 0
    )
    assert x.raw.tobytes() == a

    assert x.recalculate_checksums() >= 1
    assert x.raw.tobytes() != a


def test_ip_modify_complex(packet_factory):
    raw_hex = (
        "45 00 00 28 00 01 00 00 40 06 00 00 7f 00 00 01 7f 00 00 01"
        "00 50 00 50 00 00 00 00 00 00 00 00 50 02 20 00 00 00 00 00"
    )
    x = packet_factory(raw_hex)
    x.src_addr = "1.2.3.4"
    x.dst_addr = "5.6.7.8"
    x.src_port = 1234
    x.dst_port = 5678
    assert x.src_addr == "1.2.3.4"
    assert x.dst_addr == "5.6.7.8"
    assert x.src_port == 1234
    assert x.dst_port == 5678
    assert x.raw.tobytes() == util.fromhex(
        "45 00 00 28 00 01 00 00 40 06 00 00 01 02 03 04 05 06 07 08"
        "04 d2 16 2e 00 00 00 00 00 00 00 00 50 02 20 00 00 00 00 00"
    )


def test_ipv6_modify(packet_factory):
    raw_hex = (
        "60 00 00 00 00 08 06 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 50 00 50 00 00 00 "
        "00 00 00 00 00 50 02 20 00 00 00 00 00"
    )
    x = packet_factory(raw_hex)
    assert x.ipv6 is not None
    assert x.tcp is not None
    assert x.dst_addr == "::1"
    x.dst_addr = "2001:4860:4860::8888"
    assert x.dst_addr == "2001:4860:4860::8888"
    assert x.ipv6.dst_addr == "2001:4860:4860::8888"
    assert x.raw.tobytes() == util.fromhex(
        "60 00 00 00 00 08 06 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 "
        "20 01 48 60 48 60 00 00 00 00 00 00 00 00 88 88 00 50 00 50 00 00 00 "
        "00 00 00 00 00 50 02 20 00 00 00 00 00"
    )

    x.dst_addr = "::1"
    assert x.dst_addr == "::1"
    assert x.raw.tobytes() == util.fromhex(raw_hex)


def test_ipv6_modify_complex(packet_factory):
    raw_hex = (
        "60 00 00 00 00 08 06 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 50 00 50 00 00 00 "
        "00 00 00 00 00 50 02 20 00 00 00 00 00"
    )
    x = packet_factory(raw_hex)
    x.src_addr = "2001:4860:4860::8888"
    x.dst_addr = "2001:4860:4860::8844"
    x.src_port = 1234
    x.dst_port = 5678
    assert x.src_addr == "2001:4860:4860::8888"
    assert x.dst_addr == "2001:4860:4860::8844"
    assert x.src_port == 1234
    assert x.dst_port == 5678
    assert x.raw.tobytes() == util.fromhex(
        "60 00 00 00 00 08 06 40 20 01 48 60 48 60 00 00 00 00 00 00 00 00 88 88 "
        "20 01 48 60 48 60 00 00 00 00 00 00 00 00 88 44 04 d2 16 2e 00 00 00 "
        "00 00 00 00 00 50 02 20 00 00 00 00 00"
    )


def test_tcp_modify(packet_factory):
    raw_hex = (
        "45 00 00 28 00 01 00 00 40 06 00 00 7f 00 00 01 7f 00 00 01"
        "00 50 00 50 00 00 00 00 00 00 00 00 50 02 20 00 00 00 00 00"
    )
    x = packet_factory(raw_hex)
    assert x.tcp is not None
    assert x.tcp.header_len == 20
    assert x.tcp.dst_port == 80
    x.tcp.dst_port = 443
    assert x.tcp.dst_port == 443
    assert x.raw.tobytes() == util.fromhex(
        "45 00 00 28 00 01 00 00 40 06 00 00 7f 00 00 01 7f 00 00 01"
        "00 50 01 bb 00 00 00 00 00 00 00 00 50 02 20 00 00 00 00 00"
    )

    with pytest.raises(AttributeError):
        x.tcp.header_len = 42

    x.payload = b"test"
    assert x.payload == b"test"
    assert x.raw.tobytes() == util.fromhex(
        "45 00 00 2c 00 01 00 00 40 06 00 00 7f 00 00 01 7f 00 00 01"
        "00 50 01 bb 00 00 00 00 00 00 00 00 50 02 20 00 00 00 00 00"
        "74 65 73 74"
    )

    with pytest.raises(AttributeError):
        x.payload = 42
    assert x.payload == b"test"

    # checksum
    a = x.raw.tobytes()
    assert (
        x.recalculate_checksums(
            pydivert.CalcChecksumsOption.NO_IP_CHECKSUM | pydivert.CalcChecksumsOption.NO_TCP_CHECKSUM
        )
        >= 0
    )

    assert x.raw.tobytes() == a

    assert x.recalculate_checksums() >= 1
    assert x.raw.tobytes() != a

    # test same length raw replace.
    x.tcp.raw = x.tcp.raw.tobytes().replace(b"test", b"abcd")
    assert x.payload == b"abcd"


def test_udp_modify(packet_factory):
    raw_hex = "45 00 00 1c 00 01 00 00 40 11 00 00 7f 00 00 01 7f 00 00 0100 35 00 35 00 08 00 00"
    x = packet_factory(raw_hex)
    assert x.udp is not None
    assert x.udp.header_len == 8
    assert x.udp.dst_port == 53
    x.udp.dst_port = 5353
    assert x.udp.dst_port == 5353
    assert x.raw.tobytes() == util.fromhex(
        "45 00 00 1c 00 01 00 00 40 11 00 00 7f 00 00 01 7f 00 00 0100 35 14 e9 00 08 00 00"
    )

    with pytest.raises(AttributeError):
        x.udp.header_len = 42

    x.payload = b"test"
    assert x.payload == b"test"
    assert x.raw.tobytes() == util.fromhex(
        "45 00 00 20 00 01 00 00 40 11 00 00 7f 00 00 01 7f 00 00 0100 35 14 e9 00 0c 00 00 74 65 73 74"
    )

    with pytest.raises(AttributeError):
        x.payload = 42
    assert x.payload == b"test"

    # checksum
    a = x.raw.tobytes()
    assert (
        x.recalculate_checksums(
            pydivert.CalcChecksumsOption.NO_IP_CHECKSUM | pydivert.CalcChecksumsOption.NO_UDP_CHECKSUM
        )
        >= 0
    )
    assert x.raw.tobytes() == a

    assert x.recalculate_checksums() >= 1
    assert x.raw.tobytes() != a


def test_icmp_modify(packet_factory):
    raw_hex = "45 00 00 1c 00 01 00 00 40 01 00 00 7f 00 00 01 7f 00 00 0108 00 00 00 00 00 00 00"
    x = packet_factory(raw_hex)
    assert x.icmp is not None
    assert x.icmp.header_len == 8
    assert x.icmp.type == 8
    x.icmp.type = 0
    assert x.icmp.type == 0
    assert x.raw.tobytes() == util.fromhex(
        "45 00 00 1c 00 01 00 00 40 01 00 00 7f 00 00 01 7f 00 00 0100 00 00 00 00 00 00 00"
    )

    with pytest.raises(AttributeError):
        x.icmp.header_len = 42

    x.icmp.code = 42
    assert x.icmp.code == 42

    with pytest.raises(AttributeError):
        x.icmp.code = "bogus"
    assert x.icmp.code == 42

    # checksum
    a = x.raw.tobytes()
    assert (
        x.recalculate_checksums(
            pydivert.CalcChecksumsOption.NO_IP_CHECKSUM | pydivert.CalcChecksumsOption.NO_ICMP_CHECKSUM
        )
        >= 0
    )
    assert x.raw.tobytes() == a

    assert x.recalculate_checksums() >= 1
    assert x.raw.tobytes() != a


def test_meta():
    p = pydivert.Packet(b"", (1, 1), pydivert.Direction.OUTBOUND, loopback=True)
    assert p.is_loopback is True
    assert p.is_inbound is False
    assert p.is_outbound is True


def test_bogus(packet_factory):
    x = packet_factory(b"")
    x.src_addr = "127.0.0.1"
    x.dst_addr = "127.0.0.1"
    x.src_port = 80
    x.dst_port = 80
    x.payload = b""
    assert x.src_addr is None
    assert x.dst_addr is None
    assert x.src_port is None
    assert x.dst_port is None
    assert x.payload is None
    with pytest.raises(AttributeError):
        x.icmp.code = 42
    with pytest.raises(AttributeError):
        x.tcp.ack = True
    assert x.recalculate_checksums() == 0


def test_ipv6_truncation(packet_factory):
    # Correct IPv6 destination address
    p6 = packet_factory(b"\x60" + b"\x00" * 39)
    assert p6.address_family == socket.AF_INET6
    assert p6.src_addr == "::"
    assert p6.dst_addr == "::"

    # Truncated IPv6 destination address
    p6_trunc = packet_factory(b"\x60" + b"\x00" * 38)
    assert p6_trunc.address_family == socket.AF_INET6
    assert p6_trunc.src_addr == "::"
    assert p6_trunc.dst_addr is None

    # Fragmented...
    raw_hex = (
        "6000000005b02c80fe8000000000000002105afffeaa20a2fe800000000000000250dafffed8c1533a0000010000000"
        "580009e9d0000000d6162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70"
        "717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717"
        "273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273"
        "747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747"
        "576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576"
        "776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776"
        "162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776162"
        "636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636"
        "465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465"
        "666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666"
        "768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768"
        "696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696"
        "a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b"
        "6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6"
        "d6e6f70717273747576776162636465666768696a6b6c6d6e"
    )
    assert packet_factory(raw_hex).protocol[0] == Protocol.ICMPV6

    # HOPOPTS
    raw_hex = (
        "600000000020000100000000000000000000000000000000ff0200000000000000000000000000013a0005020000000"
        "082007ac103e8000000000000000000000000000000000000"
    )
    assert packet_factory(raw_hex).protocol[0] == Protocol.ICMPV6


def test_ipv4_fields(packet_factory):
    raw_hex = (
        "4500005426ef0000400157f9c0a82b09080808080800bbb3d73b000051a7d67d000451e408090a0b0c0d0e0f1011121"
        "31415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
    )
    ip = packet_factory(raw_hex).ipv4

    assert not ip.df
    ip.df = True
    assert ip.df
    assert ip.flags == 2
    assert ip.frag_offset == 0
    ip.flags = 3
    assert ip.flags == 3
    assert ip.mf
    assert ip.df
    assert ip.frag_offset == 0
    ip.ecn = 3
    assert ip.ecn == 3
    ip.dscp = 18
    assert ip.dscp == 18
    assert ip.diff_serv == ip.dscp
    assert ip.ecn == 3
    assert ip.tos == 75
    ip.tos = 1
    assert ip.tos == 1
    assert ip.ecn == 1
    assert ip.dscp == 0
    ip.flags = 1
    assert ip.mf
    ip.mf = False
    assert not ip.mf
    assert ip.flags == 0
    ip.frag_offset = 65
    assert ip.frag_offset == 65
    assert ip.flags == 0
    ip.flags = 7
    assert ip.frag_offset == 65
    assert ip.evil
    assert ip.reserved == ip.evil
    ip.evil = False
    assert not ip.evil
    assert ip.reserved == ip.evil
    assert ip.flags == 3
    ip.ident = 257
    assert ip.ident == 257
    assert ip.hdr_len == 5
    ip.cksum = 514
    assert ip.cksum == 514
    ip.hdr_len = 6
    assert ip.hdr_len == 6
    assert ip.header_len == 6 * 4
    ip.ttl = 4
    assert ip.ttl == 4
    ip.protocol = Protocol.FRAGMENT
    assert ip.protocol == Protocol.FRAGMENT
    with pytest.raises(ValueError):
        ip.hdr_len = 4


def test_ipv6_fields(packet_factory):
    raw_hex = (
        "6e000000003c3301fe800000000000000000000000000001ff020000000000000000000000000005590400000000010"
        "00000001321d3a95c5ffd4d184622b9f8030100240101010100000001fb8600000000000501000013000a0028000000"
        "0000000000"
    )
    ip = packet_factory(raw_hex).ipv6

    ip.traffic_class = 3
    assert ip.traffic_class == 3
    assert ip.ecn == 3
    ip.ecn = 0
    assert ip.ecn == 0
    assert ip.traffic_class == 0
    ip.diff_serv = 8
    assert ip.diff_serv == 8
    assert ip.traffic_class == 32
    ip.flow_label = 17
    assert ip.flow_label == 17
    assert ip.traffic_class == 32


def test_icmp_fields(packet_factory):
    raw_hex = (
        "4500005426ef0000400157f9c0a82b09080808080800bbb3d73b000051a7d67d000451e408090a0b0c0d0e0f1011121"
        "31415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
    )
    icmp = packet_factory(raw_hex).icmp

    icmp.cksum = 11
    assert icmp.cksum == 11


def test_tcp_fields(packet_factory):
    raw_hex = (
        "45000051476040008006f005c0a856a936f274fdd84201bb0876cfd0c19f9320501800ff8dba0000170303002400000"
        "00000000c2f53831a37ed3c3a632f47440594cab95283b558bf82cb7784344c3314"
    )
    tcp = packet_factory(raw_hex).tcp

    assert tcp.reserved == 0
    tcp.reserved = 7
    assert tcp.reserved == 7
    assert not tcp.ns
    tcp.ns = True
    assert tcp.ns
    assert tcp.reserved == 0b111
    assert tcp.header_len == tcp.data_offset * 4
    tcp.data_offset = 5
    assert tcp.data_offset == 5
    with pytest.raises(ValueError):
        tcp.data_offset = 4
    with pytest.raises(ValueError):
        tcp.data_offset = 16

    tcp.cwr = True
    assert tcp.cwr
    tcp.ece = True
    assert tcp.ece
    tcp.syn = True
    tcp.control_bits = 0x01F0
    assert not tcp.fin
    assert not tcp.syn
    assert tcp.control_bits == 0x01F0
    assert tcp.ece
    assert tcp.ns
    tcp.ns = False
    assert tcp.control_bits == 0x00F0


def test_udp_fields(packet_factory):
    raw_hex = (
        "4500004281bf000040112191c0a82b09c0a82b01c9dd0035002ef268528e01000001000000000000013801380138013"
        "807696e2d61646472046172706100000c0001"
    )
    udp = packet_factory(raw_hex).udp

    udp.cksum = 0xAAAA
    assert udp.cksum == 0xAAAA


def test_ipv6_traffic_class_flow_label_bit_sharing(packet_factory):
    # IPv6 header structure (RFC 2460):
    # Bits 0-3: Version (6)
    # Bits 4-11: Traffic Class
    # Bits 12-31: Flow Label (20 bits)

    # Create a dummy IPv6 packet
    raw = bytes(40)
    raw = b"\x60" + raw[1:]  # Version 6

    packet = packet_factory(raw)
    ipv6 = packet.ipv6
    assert ipv6 is not None

    # Initial state
    assert ipv6.traffic_class == 0
    assert ipv6.flow_label == 0

    # 1. Set Traffic Class, verify Flow Label is unchanged
    ipv6.traffic_class = 170  # 1010 1010
    assert ipv6.traffic_class == 0xAA
    assert ipv6.flow_label == 0

    # 2. Set Flow Label (including bits in the first 16-bit word), verify Traffic Class is unchanged
    # Flow label is 20 bits. Let's set some bits in the most significant 4 bits (0xF....)
    ipv6.flow_label = 987700
    assert ipv6.flow_label == 0xF1234
    assert ipv6.traffic_class == 0xAA  # Should be preserved

    # 3. Modify Traffic Class again, verify Flow Label is preserved
    ipv6.traffic_class = 85  # 0101 0101
    assert ipv6.traffic_class == 0x55
    assert ipv6.flow_label == 0xF1234  # Should be preserved

    # 4. Verify raw bytes
    # Version (4): 6 (0110)
    # Traffic Class (8): 0x55 (0101 0101)
    # Flow Label (20): 0xF1234 (1111 0001 0010 0011 0100)
    # First 32 bits: 0110 0101 0101 1111 0001 0010 0011 0100
    # Hex: 6 5 5 F 1 2 3 4 -> 0x655F1234
    first_32_bits = struct.unpack_from("!I", packet.raw, 0)[0]
    assert first_32_bits == 0x655F1234

    # 5. Verify properties derived from traffic_class
    # traffic_class 0x55 = 010101 01
    # diff_serv = 010101 = 21 (0x15)
    # ecn = 01 = 1
    assert ipv6.diff_serv == 0x15
    assert ipv6.ecn == 1

    ipv6.diff_serv = 63
    ipv6.ecn = 3
    assert ipv6.traffic_class == 0xFF
    assert ipv6.flow_label == 0xF1234
    assert struct.unpack_from("!I", packet.raw, 0)[0] == 0x6FFF1234


def test_filter_match(packet_factory):
    raw_hex = (
        "4500004281bf000040112191c0a82b09c0a82b01c9dd0035002ef268528e01000001000000000000013801380138013"
        "807696e2d61646472046172706100000c0001"
    )
    # src: 192.168.43.9, dst: 192.168.43.1
    # src_port: 51677, dst_port: 53
    p_pkt = packet_factory(raw_hex)

    assert p_pkt.matches("true")
    assert p_pkt.matches("udp and outbound")
    assert not p_pkt.matches("tcp")

    # Aggregate fields
    assert p_pkt.matches("ip.Addr == 192.168.43.9")
    assert p_pkt.matches("ip.Addr == 192.168.43.1")
    assert not p_pkt.matches("ip.Addr == 1.2.3.4")

    assert p_pkt.matches("udp.Port == 51677")
    assert p_pkt.matches("udp.Port == 53")
    assert not p_pkt.matches("udp.Port == 80")

    # Complex combinations
    assert p_pkt.matches("(udp.Port == 53) and ip.Addr == 192.168.43.9")
    assert p_pkt.matches("(udp.Port == 80 or udp.Port == 53) and ip.Addr == 192.168.43.9")
    assert not p_pkt.matches("(udp.Port == 80) and ip.Addr == 192.168.43.9")

    # Aliases
    assert p_pkt.matches("ip.Src == 192.168.43.9")
    assert p_pkt.matches("ip.Dst == 192.168.43.1")


def test_ip_addr_invalid_length(packet_factory):
    # IPv4 addresses at 12-16 and 16-20
    p4 = packet_factory(b"\x45" + b"\x00" * 9)
    assert p4.src_addr is None
    assert p4.dst_addr is None

    # Partially truncated IPv4 destination address
    p4_partial = packet_factory(b"\x45" + b"\x00" * 18)
    # address_family requires length 20, so we have to use IPv4Header directly
    assert p4_partial.address_family is None
    from pydivert.packet.ip import IPv4Header
    assert IPv4Header(p4_partial).src_addr == "0.0.0.0"
    assert IPv4Header(p4_partial).dst_addr is None

    # IPv6 addresses at 8-24 and 24-40
    p6 = packet_factory(b"\x60" + b"\x00" * 19)
    assert p6.src_addr is None
    assert p6.dst_addr is None

    # Partially truncated IPv6 destination address
    p6_partial = packet_factory(b"\x60" + b"\x00" * 31)
    assert p6_partial.address_family == socket.AF_INET6
    assert p6_partial.src_addr == "::"
    assert p6_partial.dst_addr is None


def test_ipv6_property_non_ipv6(packet_factory):
    """Test that the ipv6 property returns None when address_family is not AF_INET6."""
    ipv4_hdr = util.fromhex("45 00 00 28 00 01 00 00 40 06 00 00 7f 00 00 01 7f 00 00 01")
    packet = packet_factory(ipv4_hdr)
    assert packet.address_family == socket.AF_INET
    assert packet.ipv6 is None
