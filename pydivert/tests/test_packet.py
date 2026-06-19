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
    ip.df = True
    assert ip.df
    ip.ident = 0x1234
    assert ip.ident == 0x1234


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


def test_direction_and_layer_properties():
    from pydivert.consts import Layer

    p = pydivert.Packet(b"test", (1, 2), Direction.OUTBOUND)

    # Test direction
    assert p.direction == Direction.OUTBOUND
    assert not p.is_inbound
    assert p.is_outbound

    p.direction = Direction.INBOUND
    assert p.direction == Direction.INBOUND
    assert p.is_inbound
    assert not p.is_outbound
    assert p.wd_addr.Outbound == 0

    p.direction = Direction.OUTBOUND
    assert p.direction == Direction.OUTBOUND
    assert not p.is_inbound
    assert p.is_outbound
    assert p.wd_addr.Outbound == 1

    p.is_inbound = True
    assert p.direction == Direction.INBOUND
    assert p.wd_addr.Outbound == 0

    p.is_outbound = True
    assert p.direction == Direction.OUTBOUND
    assert p.wd_addr.Outbound == 1

    # Test layer
    assert p.layer == Layer.NETWORK

    p.layer = Layer.NETWORK_FORWARD
    assert p.layer == Layer.NETWORK_FORWARD
    assert p.wd_addr.Layer == Layer.NETWORK_FORWARD
    assert p.wd_addr.u.Network.IfIdx == 1
    assert p.wd_addr.u.Network.SubIfIdx == 2

    from pydivert.windivert_dll.structs import WinDivertAddress

    flow_obj = WinDivertAddress._Union._Flow()
    flow_obj.ProcessId = 123
    p._flow = flow_obj
    p.layer = Layer.FLOW
    assert p.layer == Layer.FLOW
    assert p.wd_addr.Layer == Layer.FLOW
    assert p.wd_addr.u.Flow.ProcessId == 123

    socket_obj = WinDivertAddress._Union._Socket()
    socket_obj.ProcessId = 456
    p._socket = socket_obj
    p.layer = Layer.SOCKET
    assert p.layer == Layer.SOCKET
    assert p.wd_addr.Layer == Layer.SOCKET
    assert p.wd_addr.u.Socket.ProcessId == 456

    reflect_obj = WinDivertAddress._Union._Reflect()
    reflect_obj.ProcessId = 789
    p._reflect = reflect_obj
    p.layer = Layer.REFLECT
    assert p.layer == Layer.REFLECT
    assert p.wd_addr.Layer == Layer.REFLECT
    assert p.wd_addr.u.Reflect.ProcessId == 789

    p.impostor = True
    assert p.is_impostor
    assert p.impostor
    assert p.wd_addr.Impostor == 1

    p.sniffed = True
    assert p.is_sniffed
    assert p.sniffed
    assert p.wd_addr.Sniffed == 1

    p.loopback = True
    assert p.is_loopback
    assert p.loopback
    assert p.wd_addr.Loopback == 1

    p.timestamp = 12345
    assert p.timestamp == 12345
    assert p.wd_addr.Timestamp == 12345

    p.event = 10
    assert p.event == 10
    assert p.wd_addr.Event == 10

    p.icmp_checksum = True
    assert p._icmp_checksum is True

    p.layer = Layer.FLOW
    p.flow = flow_obj
    assert p.flow is flow_obj
    assert p.wd_addr.u.Flow.ProcessId == 123

    p.layer = Layer.SOCKET
    p.socket = socket_obj
    assert p.socket is socket_obj
    assert p.wd_addr.u.Socket.ProcessId == 456

    p.layer = Layer.REFLECT
    p.reflect = reflect_obj
    assert p.reflect is reflect_obj
    assert p.wd_addr.u.Reflect.ProcessId == 789


# --- Hypothesis ---


@given(src=st_ipv4, dst=st_ipv4)
def test_ipv4_hypo(src, dst):
    p = create_base_ipv4_tcp()
    p.src_addr = src
    p.dst_addr = dst
    assert p.src_addr == src
    assert p.dst_addr == dst
