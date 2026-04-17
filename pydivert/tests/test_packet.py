# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of either:
#
# 1) The GNU Lesser General Public License as published by the Free
#    Software Foundation, either version 3 of the License, or (at your
#    option) any later version.
#
# 2) The GNU General Public License as published by the Free Software
#    Foundation, either version 2 of the License, or (at your option)
#    any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License and the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# and the GNU General Public License along with this program.  If not,
# see <https://www.gnu.org/licenses/>.

import socket
import struct

import pytest
from hypothesis import example, given
from hypothesis.strategies import binary

import pydivert
from pydivert import util
from pydivert.consts import Direction, Protocol


def p(raw):
    return pydivert.Packet(raw, (0, 0), Direction.OUTBOUND)


ipv4_hdr = util.fromhex("45200028fa8d40002906368b345ad4f0c0a856a4")
ipv6_hdr = util.fromhex("600d684a00280640fc000002000000020000000000000001fc000002000000010000000000000001")


@given(raw=binary(min_size=0, max_size=1600))
@example(raw=b"`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
@example(raw=b"E\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
def test_fuzz(raw):
    packets = [p(raw), p(ipv4_hdr + raw), p(ipv6_hdr + raw)]
    for x in packets:
        assert repr(x)
        # Accessing properties shouldn't crash regardless of raw data
        _ = x.src_addr
        _ = x.dst_addr
        _ = x.src_port
        _ = x.dst_port
        _ = x.payload
        _ = x.protocol
        _ = x.ipv4
        _ = x.ipv6
        _ = x.tcp
        _ = x.udp
        _ = x.icmp
        try:
            _ = x.is_checksum_valid
        except (OSError, FileNotFoundError):
            # This can fail if the driver is not loaded
            pass


def test_ipv6_tcp():
    raw = util.fromhex(
        "600d684a007d0640fc000002000000020000000000000001fc000002000000010000000000000001a9a01f90021b638"
        "dba311e8e801800cfc92e00000101080a801da522801da522474554202f68656c6c6f2e74787420485454502f312e31"
        "0d0a557365722d4167656e743a206375726c2f372e33382e300d0a486f73743a205b666330303a323a303a313a3a315"
        "d3a383038300d0a4163636570743a202a2f2a0d0a0d0a"
    )
    x = p(raw)
    assert x.address_family == socket.AF_INET6
    assert x.protocol[0] == Protocol.TCP
    assert x.src_addr == "fc00:2:0:2::1"
    assert x.dst_addr == "fc00:2:0:1::1"
    assert x.src_port == 43424
    assert x.dst_port == 8080
    assert not x.ipv4
    assert x.ipv6
    assert x.tcp
    assert not x.udp
    assert not x.icmp
    assert x.payload == (
        b"GET /hello.txt HTTP/1.1\r\nUser-Agent: curl/7.38.0\r\nHost: [fc00:2:0:1::1]:8080\r\nAccept: */*\r\n\r\n"
    )
    assert x.ip.packet_len == 165
    assert repr(x)


def test_ipv4_udp():
    raw = util.fromhex(
        "4500004281bf000040112191c0a82b09c0a82b01c9dd0035002ef268528e01000001000000000000013801380138013"
        "807696e2d61646472046172706100000c0001"
    )
    x = p(raw)
    assert x.address_family == socket.AF_INET
    assert x.protocol[0] == Protocol.UDP
    assert x.src_addr == "192.168.43.9"
    assert x.dst_addr == "192.168.43.1"
    assert x.src_port == 51677
    assert x.dst_port == 53
    assert x.ipv4
    assert not x.ipv6
    assert not x.tcp
    assert x.udp
    assert not x.icmp
    assert x.payload == util.fromhex("528e01000001000000000000013801380138013807696e2d61646472046172706100000c0001")
    assert x.udp.payload_len == 38
    assert repr(x)


def test_icmp_ping():
    raw = util.fromhex(
        "4500005426ef0000400157f9c0a82b09080808080800bbb3d73b000051a7d67d000451e408090a0b0c0d0e0f1011121"
        "31415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
    )
    x = p(raw)
    assert x.address_family == socket.AF_INET
    assert x.protocol[0] == Protocol.ICMP
    assert x.src_addr == "192.168.43.9"
    assert x.dst_addr == "8.8.8.8"
    assert x.src_port is None
    assert x.dst_port is None
    assert x.icmp.type == 8
    assert x.icmp.code == 0
    assert x.ipv4
    assert not x.ipv6
    assert not x.tcp
    assert not x.udp
    assert x.icmpv4
    assert not x.icmpv6
    assert x.payload == util.fromhex(
        "d73b000051a7d67d000451e408090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232"
        "425262728292a2b2c2d2e2f3031323334353637"
    )
    assert repr(x)


def test_icmpv6_unreachable():
    raw = util.fromhex(
        "6000000000443a3d3ffe05010410000002c0dffffe47033e3ffe050700000001020086fffe0580da010413520000000"
        "060000000001411013ffe050700000001020086fffe0580da3ffe05010410000002c0dffffe47033ea07582a40014cf"
        "470a040000f9c8e7369d250b00"
    )
    x = p(raw)
    assert x.address_family == socket.AF_INET6
    assert x.protocol[0] == Protocol.ICMPV6
    assert x.src_addr == "3ffe:501:410:0:2c0:dfff:fe47:33e"
    assert x.dst_addr == "3ffe:507:0:1:200:86ff:fe05:80da"
    assert x.src_port is None
    assert x.dst_port is None
    assert x.icmp.type == 1
    assert x.icmp.code == 4
    assert not x.ipv4
    assert x.ipv6
    assert not x.tcp
    assert not x.udp
    assert not x.icmpv4
    assert x.icmpv6
    assert x.payload == util.fromhex(
        "0000000060000000001411013ffe050700000001020086fffe0580da3ffe05010410000002c0dffff"
        "e47033ea07582a40014cf470a040000f9c8e7369d250b00"
    )
    assert repr(x)


def test_ipv4_tcp_modify():
    raw = util.fromhex(
        "45000051476040008006f005c0a856a936f274fdd84201bb0876cfd0c19f9320501800ff8dba0000170303002400000"
        "00000000c2f53831a37ed3c3a632f47440594cab95283b558bf82cb7784344c3314"
    )
    x = p(raw)
    assert x.protocol[0] == Protocol.TCP

    # src_addr
    x.src_addr = "1.2.3.4"
    with pytest.raises(OSError):
        x.src_addr = "::1"
    with pytest.raises(TypeError):
        x.src_addr = 42
    assert x.src_addr == "1.2.3.4"

    # dst_addr
    x.dst_addr = "4.3.2.1"
    with pytest.raises(OSError):
        x.dst_addr = "::1"
    assert x.dst_addr == "4.3.2.1"

    # src_port
    x.src_port = 42
    with pytest.raises((TypeError, struct.error)):
        x.src_port = "bogus"
    assert x.src_port == 42

    # dst_port
    x.dst_port = 43
    with pytest.raises((TypeError, struct.error)):
        x.dst_port = "bogus"
    assert x.dst_port == 43

    # tcp_ack (others follow trivially)
    x.tcp.ack = False
    assert x.tcp.ack is False
    x.tcp.ack = True
    assert x.tcp.ack is True

    # payload
    x.payload = b"test"
    with pytest.raises((TypeError, struct.error)):
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


def test_ipv6_udp_modify():
    raw = util.fromhex(
        "60000000002711403ffe050700000001020086fffe0580da3ffe0501481900000000000000000042095d0035002746b"
        "700060100000100000000000003777777057961686f6f03636f6d00000f0001"
    )
    x = p(raw)
    assert x.protocol[0] == Protocol.UDP

    # src_addr
    x.src_addr = "::1"
    with pytest.raises(OSError):
        x.src_addr = "127.0.0.1"
    with pytest.raises(TypeError):
        x.src_addr = 42
    assert x.src_addr == "::1"

    # dst_addr
    x.dst_addr = "::2"
    with pytest.raises(OSError):
        x.dst_addr = "bogus"
    assert x.dst_addr == "::2"

    # src_port
    x.src_port = 42
    with pytest.raises((TypeError, struct.error)):
        x.src_port = "bogus"
    assert x.src_port == 42

    # dst_port
    x.dst_port = 43
    with pytest.raises((TypeError, struct.error)):
        x.dst_port = "bogus"
    assert x.dst_port == 43

    # payload
    x.payload = b"test"
    with pytest.raises((TypeError, struct.error)):
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

    assert x.recalculate_checksums() == 1
    assert x.raw.tobytes() != a


def test_icmp_modify():
    raw = util.fromhex(
        "4500005426ef0000400157f9c0a82b09080808080800bbb3d73b000051a7d67d000451e408090a0b0c0d0e0f1011121"
        "31415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
    )
    x = p(raw)
    assert x.protocol[0] == Protocol.ICMP

    # src_addr
    x.src_addr = "1.2.3.4"
    with pytest.raises(OSError):
        x.src_addr = "::1"
    with pytest.raises(TypeError):
        x.src_addr = 42
    assert x.src_addr == "1.2.3.4"

    # dst_addr
    x.dst_addr = "4.3.2.1"
    with pytest.raises(OSError):
        x.dst_addr = "::1"
    assert x.dst_addr == "4.3.2.1"

    # payload
    x.payload = b"test"
    with pytest.raises((TypeError, struct.error)):
        x.payload = 42
    assert x.payload == b"test"

    # icmp
    x.icmp.type = 42
    with pytest.raises((TypeError, struct.error)):
        x.icmp.type = "bogus"
    assert x.icmp.type == 42
    x.icmp.code = 42
    with pytest.raises((TypeError, struct.error)):
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
    p = pydivert.Packet(b"", (1, 1), Direction.OUTBOUND, loopback=True)
    assert p.is_outbound
    assert not p.is_inbound
    assert p.is_loopback

    p2 = pydivert.Packet(b"", (2, 2), Direction.INBOUND)
    assert not p2.is_outbound
    assert p2.is_inbound
    assert not p2.is_loopback


def test_bogus():
    x = p(b"")
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


def test_ipv6_extension_headers():
    # AH Header
    raw = util.fromhex(
        "6e000000003c3301fe800000000000000000000000000001ff020000000000000000000000000005590400000000010"
        "00000001321d3a95c5ffd4d184622b9f8030100240101010100000001fb8600000000000501000013000a0028000000"
        "0000000000"
    )
    assert p(raw).protocol[0] == 89

    # Fragmented...
    raw = util.fromhex(
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
        "d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e"
        "6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f7"
        "0717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f7071"
        "7273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f7071727"
        "3747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f7071727374"
        "7576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f7071727374757"
        "6776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f7071727374757677"
        "6162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f7071727374757677616"
        "2636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f7071727374757677616263"
        "6465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f7071727374757677616263646"
        "5666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f7071727374757677616263646566"
        "6768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f7071727374757677616263646566676"
        "8696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f7071727374757677616263646566676869"
        "6a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6"
        "b6c6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c"
        "6d6e6f70717273747576776162636465666768696a6b6c6d6e6f70717273747576776162636465666768696a6b6c6d6"
        "e6f70717273747576776162636465666768696a6b6c6d6e"
    )
    assert p(raw).protocol[0] == Protocol.ICMPV6

    # HOPOPTS
    raw = util.fromhex(
        "600000000020000100000000000000000000000000000000ff0200000000000000000000000000013a0005020000000"
        "082007ac103e8000000000000000000000000000000000000"
    )
    assert p(raw).protocol[0] == Protocol.ICMPV6


def test_ipv4_fields():
    raw = util.fromhex(
        "4500005426ef0000400157f9c0a82b09080808080800bbb3d73b000051a7d67d000451e408090a0b0c0d0e0f1011121"
        "31415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
    )
    ip = p(raw).ipv4

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


def test_ipv6_fields():
    raw = util.fromhex(
        "6e000000003c3301fe800000000000000000000000000001ff020000000000000000000000000005590400000000010"
        "00000001321d3a95c5ffd4d184622b9f8030100240101010100000001fb8600000000000501000013000a0028000000"
        "0000000000"
    )
    ip = p(raw).ipv6

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


def test_icmp_fields():
    raw = util.fromhex(
        "4500005426ef0000400157f9c0a82b09080808080800bbb3d73b000051a7d67d000451e408090a0b0c0d0e0f1011121"
        "31415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
    )
    icmp = p(raw).icmp

    icmp.cksum = 11
    assert icmp.cksum == 11


def test_tcp_fields():
    raw = util.fromhex(
        "45000051476040008006f005c0a856a936f274fdd84201bb0876cfd0c19f9320501800ff8dba0000170303002400000"
        "00000000c2f53831a37ed3c3a632f47440594cab95283b558bf82cb7784344c3314"
    )
    tcp = p(raw).tcp

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


def test_udp_fields():
    raw = util.fromhex(
        "4500004281bf000040112191c0a82b09c0a82b01c9dd0035002ef268528e01000001000000000000013801380138013"
        "807696e2d61646472046172706100000c0001"
    )
    udp = p(raw).udp

    udp.cksum = 0xAAAA
    assert udp.cksum == 0xAAAA


def test_ipv6_traffic_class_flow_label_bit_sharing():
    # IPv6 header structure (RFC 2460):
    # Bits 0-3: Version (6)
    # Bits 4-11: Traffic Class
    # Bits 12-31: Flow Label (20 bits)

    # Create a dummy IPv6 packet
    raw = bytes(40)
    raw = b"\x60" + raw[1:]  # Version 6

    packet = pydivert.Packet(raw, (0, 0), Direction.OUTBOUND)
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


def test_filter_match():
    raw = util.fromhex(
        "4500004281bf000040112191c0a82b09c0a82b01c9dd0035002ef268528e01000001000000000000013801380138013"
        "807696e2d61646472046172706100000c0001"
    )
    p = pydivert.Packet(raw, (1, 1), Direction.OUTBOUND)

    assert p.matches("true")
    assert p.matches("udp and outbound")
    assert not p.matches("tcp")


def test_ip_addr_invalid_length():
    # IPv4 addresses at 12-16 and 16-20
    p4 = p(b"\x45" + b"\x00" * 9)
    assert p4.src_addr is None
    assert p4.dst_addr is None

    # Partially truncated IPv4 destination address
    p4_partial = p(b"\x45" + b"\x00" * 18)
    # address_family requires length 20, so we have to use IPv4Header directly
    assert p4_partial.address_family is None
    assert pydivert.packet.ip.IPv4Header(p4_partial).src_addr == "0.0.0.0"
    assert pydivert.packet.ip.IPv4Header(p4_partial).dst_addr is None

    # IPv6 addresses at 8-24 and 24-40
    p6 = p(b"\x60" + b"\x00" * 19)
    assert p6.src_addr is None
    assert p6.dst_addr is None

    # Partially truncated IPv6 destination address
    p6_partial = p(b"\x60" + b"\x00" * 31)
    assert p6_partial.address_family == socket.AF_INET6
    assert p6_partial.src_addr == "::"
    assert p6_partial.dst_addr is None


def test_ipv6_property_non_ipv6():
    """Test that the ipv6 property returns None when address_family is not AF_INET6."""
    packet = p(ipv4_hdr)
    assert packet.address_family == socket.AF_INET
    assert packet.ipv6 is None
