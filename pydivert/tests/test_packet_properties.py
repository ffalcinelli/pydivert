# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils

import socket

from hypothesis import given
from hypothesis import strategies as st

from pydivert.consts import Direction
from pydivert.packet import Packet

# Strategies
st_ipv4 = st.ip_addresses(v=4).map(str)
st_ipv6 = st.ip_addresses(v=6).map(str)
st_port = st.integers(min_value=0, max_value=65535)
st_payload = st.binary(min_size=0, max_size=1500)

def create_base_ipv4_tcp():
    raw = bytearray(b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    raw += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00"
    return Packet(raw)

def create_base_ipv6_udp():
    raw = bytearray(b"\x60\x00\x00\x00\x00\x08\x11\x40") # IPv6, next hdr UDP (17=0x11)
    raw += socket.inet_pton(socket.AF_INET6, "::1")
    raw += socket.inet_pton(socket.AF_INET6, "::1")
    raw += b"\x00\x00\x00\x00\x00\x08\x00\x00" # UDP header (len 8)
    return Packet(raw)

@given(src=st_ipv4, dst=st_ipv4)
def test_ipv4_address_property(src, dst):
    p = create_base_ipv4_tcp()
    p.src_addr = src
    p.dst_addr = dst
    assert p.src_addr == src
    assert p.dst_addr == dst
    assert p.address_family == socket.AF_INET

@given(src=st_ipv6, dst=st_ipv6)
def test_ipv6_address_property(src, dst):
    p = create_base_ipv6_udp()
    p.src_addr = src
    p.dst_addr = dst
    # IPv6 canonicalization can be tricky, but socket.inet_ntop(socket.inet_pton) should match
    expected_src = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, src))
    expected_dst = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, dst))
    assert p.src_addr == expected_src
    assert p.dst_addr == expected_dst
    assert p.address_family == socket.AF_INET6

@given(src_p=st_port, dst_p=st_port)
def test_tcp_port_property(src_p, dst_p):
    p = create_base_ipv4_tcp()
    p.src_port = src_p
    p.dst_port = dst_p
    assert p.src_port == src_p
    assert p.dst_port == dst_p

@given(src_p=st_port, dst_p=st_port)
def test_udp_port_property(src_p, dst_p):
    p = create_base_ipv6_udp()
    p.src_port = src_p
    p.dst_port = dst_p
    assert p.src_port == src_p
    assert p.dst_port == dst_p

@given(payload=st_payload)
def test_payload_property(payload):
    p = create_base_ipv4_tcp()
    p.payload = payload
    assert p.payload == payload
    # Check that IP length was updated
    assert p.ipv4.packet_len == 40 + len(payload)

@given(payload=st_payload)
def test_checksum_recalculation_ipv4_tcp(payload):
    p = create_base_ipv4_tcp()
    p.payload = payload
    p.recalculate_checksums()
    assert p.is_checksum_valid

@given(payload=st_payload)
def test_checksum_recalculation_ipv6_udp(payload):
    p = create_base_ipv6_udp()
    p.payload = payload
    p.recalculate_checksums()
    assert p.is_checksum_valid

@given(loopback=st.booleans(), impostor=st.booleans(), outbound=st.booleans())
def test_packet_metadata_properties(loopback, impostor, outbound):
    p = create_base_ipv4_tcp()
    p.is_loopback = loopback
    p.is_impostor = impostor
    p.direction = Direction.OUTBOUND if outbound else Direction.INBOUND

    assert p.is_loopback == loopback
    assert p.is_impostor == impostor
    assert p.is_outbound == outbound
    assert p.is_inbound == (not outbound)
