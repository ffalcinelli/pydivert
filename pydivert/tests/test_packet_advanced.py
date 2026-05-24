# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import pydivert
from pydivert.consts import Direction, Layer


def test_packet_properties_setters():
    """Test all setters in Packet class to increase coverage of packet/__init__.py."""
    # 40 bytes (20 IP + 20 TCP)
    raw = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
        + b"\x00\x50\x1f\x90\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x91\x7c\x00\x00"
    )
    p = pydivert.Packet(raw)
    assert p.tcp is not None
    p.interface = (1, 2)
    assert p.interface == (1, 2)
    p.interface = 5
    assert p.interface == (5, 0)

    # Direction
    p.direction = Direction.INBOUND
    assert p.direction == Direction.INBOUND
    p.direction = Direction.OUTBOUND
    assert p.direction == Direction.OUTBOUND

    # Flags
    p.is_loopback = True
    assert p.is_loopback is True
    p.is_loopback = False
    assert p.is_loopback is False

    p.is_impostor = True
    assert p.is_impostor is True

    p.is_sniffed = True
    assert p.is_sniffed is True

    # Checksums
    p.recalculate_checksums()
    p.ip_checksum = True
    assert p.ip_checksum is True
    p.tcp_checksum = True
    assert p.tcp_checksum is True
    p.udp_checksum = True
    assert p.udp_checksum is True

    # Timestamp
    p.timestamp = 123456789
    assert p.timestamp == 123456789

    # Layer and Event
    p.layer = Layer.FLOW
    assert p.layer == Layer.FLOW
    p.event = 1
    assert p.event == 1


def test_packet_repr_edge_cases():
    """Test __repr__ with various packet types."""
    # UDP
    ip_header = b"\x45\x00\x00\x1c\x00\x00\x40\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
    udp_header = b"\x00\x35\x00\x35\x00\x08\x00\x00"
    p_udp = pydivert.Packet(ip_header + udp_header)
    assert "UDP" in repr(p_udp)

    # ICMP
    icmp_ip_header = b"\x45\x00\x00\x1c\x00\x00\x40\x00\x40\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
    icmp_header = b"\x08\x00\xf7\xff\x00\x00\x00\x00"
    p_icmp = pydivert.Packet(icmp_ip_header + icmp_header)
    assert "ICMP" in repr(p_icmp)

    # Unknown
    p_unknown = pydivert.Packet(b"\x45\x00\x00\x14\x00\x00\x40\x00\x40\xff\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    assert "Unknown" in repr(p_unknown) or "255" in repr(p_unknown)


def test_packet_raw_setter():
    """Test raw setter and cache invalidation."""
    p = pydivert.Packet(b"\x45" + b"\x00" * 19)
    assert p.ipv4 is not None

    # Change first byte to non-IPv4
    p.raw = b"\x00" * 20
    assert p.ipv4 is None


def test_packet_address_family_invalid():
    """Test address_family on too short packet."""
    p = pydivert.Packet(b"\x45")
    assert p.address_family is None


def test_packet_unknown_protocol_repr():
    """Test __repr__ with an unknown protocol number."""
    # IPv4 with protocol 253 (Reserved for experimentation)
    raw = b"\x45\x00\x00\x14\x00\x00\x40\x00\x40\xfd\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
    p = pydivert.Packet(raw)
    r = repr(p)
    assert "253" in r or "Unknown" in r
