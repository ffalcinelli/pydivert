import socket

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

import pydivert
import pydivert.jit
from pydivert import util
from pydivert.consts import Direction

# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils

# --- Helpers ---


def p(raw):
    return pydivert.Packet(raw, (0, 0), Direction.OUTBOUND)


ipv4_hdr = util.fromhex("45200028fa8d40002906368b345ad4f0c0a856a4")
ipv6_hdr = util.fromhex("600d684a00280640fc000002000000020000000000000001fc000002000000010000000000000001")

# Strategies
st_ipv4 = st.ip_addresses(v=4).map(str)
st_ipv6 = st.ip_addresses(v=6).map(str)
st_port = st.integers(min_value=0, max_value=65535)
st_payload = st.binary(min_size=0, max_size=1500)


def create_base_ipv4_tcp():
    raw = bytearray(b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    raw += b"\x00\x50\x1f\x90\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x91\x7c\x00\x00"
    return pydivert.Packet(raw)


# --- Fuzzing & Basic Parsing ---


@given(raw=st.binary(min_size=0, max_size=1600))
@example(raw=b"`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
@example(raw=b"E\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
def test_fuzz(raw):
    packets = [p(raw), p(ipv4_hdr + raw), p(ipv6_hdr + raw)]
    for x in packets:
        assert repr(x)
        _ = x.src_addr
        _ = x.dst_addr
        _ = x.payload
        try:
            _ = x.is_checksum_valid
        except (OSError, FileNotFoundError):
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
    assert x.src_addr == "fc00:2:0:2::1"
    assert x.dst_addr == "fc00:2:0:1::1"
    assert x.src_port == 43424
    assert x.dst_port == 8080
    assert x.tcp
    assert x.payload.startswith(b"GET /hello.txt HTTP/1.1")


# --- Modification & Zerocopy ---


def test_zerocopy_modification():
    raw = bytearray(b"E\x00\x00\x1c\x00\x01\x00\x00@\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    raw += b"\x04\xd2\x00P\x00\x08\x00\x00"
    p = pydivert.Packet(raw)
    p.src_addr = "10.0.0.1"
    assert raw[12:16] == socket.inet_pton(socket.AF_INET, "10.0.0.1")
    p.src_port = 8888
    assert raw[20:22] == b"\x22\xb8"
    p.payload = b"test"
    assert p.payload == b"test"
    assert len(p.raw) == 32


def test_payload_modification_different_length():
    raw = bytearray(b"E\x00\x00\x1f\x00\x00\x40\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    raw += b"\x12\x34\x00\x50\x00\x0b\x00\x00" + b"abc"
    packet = pydivert.Packet(raw)
    assert packet.payload == b"abc"
    packet.payload = b"defgh"
    assert packet.payload == b"defgh"
    assert len(packet.raw) == 33
    assert packet.ipv4 is not None
    assert packet.ipv4.packet_len == 33
    assert packet.udp is not None
    assert packet.udp.payload_len == 5


# --- Checksums ---


def test_checksum_recalculation():
    raw = bytearray(b"E\x00\x00\x1c\x00\x01\x00\x00@\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    raw += b"\x12\x34\x12\x34\x00\x08\x00\x00"
    p = pydivert.Packet(raw)
    p.recalculate_checksums()
    assert p.is_checksum_valid
    assert p.ipv4 is not None
    p.ipv4.ttl = (p.ipv4.ttl + 1) % 256
    assert not p.is_checksum_valid
    p.recalculate_checksums()
    assert p.is_checksum_valid


# --- JIT ---


def test_jit_evaluation():
    raw = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
        + b"\x00\x50\x1f\x90\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x91\x7c\x00\x00"
    )
    packet = pydivert.Packet(raw)
    assert pydivert.jit.compile_filter("True")(packet) is True
    assert pydivert.jit.compile_filter("packet.tcp.src_port == 80")(packet) is True
    assert pydivert.jit.compile_filter("1 + 2 == 3")(packet) is True


# --- IPv4 Fields ---


def test_ipv4_fields():
    p = create_base_ipv4_tcp()
    ip = p.ipv4
    ip.ttl = 64
    assert ip.ttl == 64
    ip.ident = 0x1234
    assert ip.ident == 0x1234


def test_ipv4_fragmentation_flags():
    p = create_base_ipv4_tcp()
    ip = p.ipv4

    # Reset all flags
    ip.rf = False
    ip.df = False
    ip.mf = False

    # Check initial state
    assert not ip.rf
    assert not ip.df
    assert not ip.mf
    assert not ip.reserved

    # Test rf (and reserved alias)
    ip.rf = True
    assert ip.rf
    assert ip.reserved
    assert not ip.df
    assert not ip.mf
    ip.reserved = False
    assert not ip.rf
    assert not ip.reserved

    # Test df
    ip.df = True
    assert ip.df
    assert not ip.rf
    assert not ip.mf
    ip.df = False
    assert not ip.df

    # Test mf
    ip.mf = True
    assert ip.mf
    assert not ip.rf
    assert not ip.df
    ip.mf = False
    assert not ip.mf

    # Set combinations
    ip.rf = True
    ip.df = True
    assert ip.rf
    assert ip.df
    assert not ip.mf


# --- TCP Fields ---


def test_tcp_fields():
    p = create_base_ipv4_tcp()
    tcp = p.tcp
    tcp.syn = True
    assert tcp.syn
    tcp.ack = False
    assert not tcp.ack
    tcp.window = 1024
    assert tcp.window == 1024

    with pytest.raises(ValueError, match="TCP data offset must be between 5 and 15"):
        tcp.data_offset = 4

    with pytest.raises(ValueError, match="TCP data offset must be between 5 and 15"):
        tcp.data_offset = 16


# --- Metadata ---


def test_metadata():
    p = pydivert.Packet(b"E" + b"\x00" * 19, (1, 2), Direction.INBOUND, loopback=True)
    assert p.is_inbound
    assert p.is_loopback
    assert p.interface == (1, 2)


# --- Hypothesis ---


@given(src=st_ipv4, dst=st_ipv4)
def test_ipv4_hypo(src, dst):
    p = create_base_ipv4_tcp()
    p.src_addr = src
    p.dst_addr = dst
    assert p.src_addr == src
    assert p.dst_addr == dst


def test_header_raw_modification():
    p = create_base_ipv4_tcp()
    assert p.ipv4 is not None
    original_len = len(p.ipv4.raw)

    # same length
    new_raw = bytearray([0x12] * original_len)
    p.ipv4.raw = new_raw
    assert bytes(p.ipv4.raw) == new_raw

    # different length
    p = create_base_ipv4_tcp()
    assert p.ipv4 is not None
    new_raw = bytearray([0x45, 0x00, 0x00, 0x29] + [0x34] * (original_len - 4 + 1))
    p.ipv4.raw = new_raw
    assert p.ipv4.packet_len == len(p.raw)
    assert getattr(p, "_ip_checksum", False) is False

    # PayloadMixin and PortMixin

    from pydivert.packet.header import PayloadMixin, PortMixin

    class DummyProtocol(PortMixin, PayloadMixin):
        def __init__(self):
            self._raw = bytearray([0] * 20)

        @property
        def raw(self):
            return memoryview(self._raw)

        @raw.setter
        def raw(self, val):
            self._raw = bytearray(val)

        @property
        def header_len(self):
            return 8

    proto = DummyProtocol()
    assert proto.src_port == 0
    proto.src_port = 80
    assert proto.src_port == 80
    assert proto.dst_port == 0
    proto.dst_port = 8080
    assert proto.dst_port == 8080
    assert len(proto.payload) == 12
    proto.payload = bytearray([1] * 12)
    assert len(proto.payload) == 12
    assert proto.payload[0] == 1
    proto.payload = bytearray([2] * 10)
    assert len(proto.payload) == 10
    assert proto.payload[0] == 2
