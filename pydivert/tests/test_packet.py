# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of either:
#
#   - the GNU Lesser General Public License as published by the Free
#     Software Foundation, either version 3 of the License, or (at your
#     option) any later version.
#
#   - the GNU General Public License as published by the Free Software
#     Foundation, either version 2 of the License, or (at your option) any
#     later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License and GNU General Public License for
# more details.
#
# You should have received a copy of the GNU Lesser General Public
# License and GNU General Public License along with this program.  If
# not, see <https://www.gnu.org/licenses/>.

import socket

import pytest

import pydivert
from pydivert import util


def p(raw):
    return pydivert.Packet(raw, (1, 1), pydivert.Direction.OUTBOUND)


def test_ip_modify():
    raw = util.fromhex(
        "45 00 00 28 00 01 00 00 40 06 00 00 7f 00 00 01 7f 00 00 01"
        "00 50 00 50 00 00 00 00 00 00 00 00 50 02 20 00 00 00 00 00"
    )
    x = p(raw)
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
            pydivert.CalcChecksumsOption.NO_IP_CHECKSUM
            | pydivert.CalcChecksumsOption.NO_TCP_CHECKSUM
        )
        >= 0
    )
    assert x.raw.tobytes() == a

    assert x.recalculate_checksums() >= 1
    assert x.raw.tobytes() != a


def test_ip_modify_complex():
    raw = util.fromhex(
        "45 00 00 28 00 01 00 00 40 06 00 00 7f 00 00 01 7f 00 00 01"
        "00 50 00 50 00 00 00 00 00 00 00 00 50 02 20 00 00 00 00 00"
    )
    x = p(raw)
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


def test_ipv6_modify():
    raw = util.fromhex(
        "60 00 00 00 00 08 06 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 50 00 50 00 00 00 "
        "00 00 00 00 00 50 02 20 00 00 00 00 00"
    )
    x = p(raw)
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
    assert x.raw.tobytes() == raw


def test_ipv6_modify_complex():
    raw = util.fromhex(
        "60 00 00 00 00 08 06 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 50 00 50 00 00 00 "
        "00 00 00 00 00 50 02 20 00 00 00 00 00"
    )
    x = p(raw)
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


def test_tcp_modify():
    raw = util.fromhex(
        "45 00 00 28 00 01 00 00 40 06 00 00 7f 00 00 01 7f 00 00 01"
        "00 50 00 50 00 00 00 00 00 00 00 00 50 02 20 00 00 00 00 00"
    )
    x = p(raw)
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
            pydivert.CalcChecksumsOption.NO_IP_CHECKSUM
            | pydivert.CalcChecksumsOption.NO_TCP_CHECKSUM
        )
        >= 0
    )

    assert x.raw.tobytes() == a

    assert x.recalculate_checksums() >= 1
    assert x.raw.tobytes() != a

    # test same length raw replace.
    x.tcp.raw = x.tcp.raw.tobytes().replace(b"test", b"abcd")
    assert x.payload == b"abcd"


def test_udp_modify():
    raw = util.fromhex(
        "45 00 00 1c 00 01 00 00 40 11 00 00 7f 00 00 01 7f 00 00 01" "00 35 00 35 00 08 00 00"
    )
    x = p(raw)
    assert x.udp is not None
    assert x.udp.header_len == 8
    assert x.udp.dst_port == 53
    x.udp.dst_port = 5353
    assert x.udp.dst_port == 5353
    assert x.raw.tobytes() == util.fromhex(
        "45 00 00 1c 00 01 00 00 40 11 00 00 7f 00 00 01 7f 00 00 01" "00 35 14 e9 00 08 00 00"
    )

    with pytest.raises(AttributeError):
        x.udp.header_len = 42

    x.payload = b"test"
    assert x.payload == b"test"
    assert x.raw.tobytes() == util.fromhex(
        "45 00 00 20 00 01 00 00 40 11 00 00 7f 00 00 01 7f 00 00 01"
        "00 35 14 e9 00 0c 00 00 74 65 73 74"
    )

    with pytest.raises(AttributeError):
        x.payload = 42
    assert x.payload == b"test"

    # checksum
    a = x.raw.tobytes()
    assert (
        x.recalculate_checksums(
            pydivert.CalcChecksumsOption.NO_IP_CHECKSUM
            | pydivert.CalcChecksumsOption.NO_UDP_CHECKSUM
        )
        >= 0
    )
    assert x.raw.tobytes() == a

    assert x.recalculate_checksums() >= 1
    assert x.raw.tobytes() != a


def test_icmp_modify():
    raw = util.fromhex(
        "45 00 00 1c 00 01 00 00 40 01 00 00 7f 00 00 01 7f 00 00 01" "08 00 00 00 00 00 00 00"
    )
    x = p(raw)
    assert x.icmp is not None
    assert x.icmp.header_len == 8
    assert x.icmp.type == 8
    x.icmp.type = 0
    assert x.icmp.type == 0
    assert x.raw.tobytes() == util.fromhex(
        "45 00 00 1c 00 01 00 00 40 01 00 00 7f 00 00 01 7f 00 00 01" "00 00 00 00 00 00 00 00"
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
            pydivert.CalcChecksumsOption.NO_IP_CHECKSUM
            | pydivert.CalcChecksumsOption.NO_ICMP_CHECKSUM
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


def test_ipv6_truncation():
    # Correct IPv6 destination address
    p6 = p(b"\x60" + b"\x00" * 39)
    assert p6.address_family == socket.AF_INET6
    assert p6.src_addr == "::"
    assert p6.dst_addr == "::"

    # Truncated IPv6 destination address
    p6_trunc = p(b"\x60" + b"\x00" * 38)
    assert p6_trunc.address_family == socket.AF_INET6
    assert p6_trunc.src_addr == "::"
    assert p6_trunc.dst_addr is None

    # Partially truncated IPv6 destination address
    p6_partial = p(b"\x60" + b"\x00" * 31)
    assert p6_partial.address_family == socket.AF_INET6
    assert p6_partial.src_addr == "::"
    assert p6_partial.dst_addr is None


def test_ipv6_property_non_ipv6():
    """Test that the ipv6 property returns None when address_family is not AF_INET6."""
    ipv4_hdr = util.fromhex("45 00 00 28 00 01 00 00 40 06 00 00 7f 00 00 01 7f 00 00 01")
    packet = p(ipv4_hdr)
    assert packet.address_family == socket.AF_INET
    assert packet.ipv6 is None
