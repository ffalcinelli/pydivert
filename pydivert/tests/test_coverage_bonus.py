import sys

import pytest

from pydivert.consts import Layer
from pydivert.packet import Packet


@pytest.mark.skipif(sys.platform != "win32", reason="Checksum logic diff")
def test_icmp_checksum_verification():
    # ICMPv4 Echo Request
    raw = bytearray(
        b"\x45\x00\x00\x1c" # IPv4
        b"\x00\x01\x00\x00"
        b"\x40\x01\x00\x00" # cksum 0
        b"\x7f\x00\x00\x01" # 127.0.0.1
        b"\x7f\x00\x00\x01"
        b"\x08\x00\x00\x00" # ICMP type 8, code 0, cksum 0
        b"\x12\x34\x00\x01" # ID, Seq
    )

    p = Packet(raw, layer=Layer.NETWORK)
    assert not p.is_checksum_valid

    p.recalculate_checksums()
    assert p.is_checksum_valid

    # Corrupt ICMP
    p.raw[20] = 0x00 # type 0 (Echo Reply)
    assert not p.is_checksum_valid

    p.recalculate_checksums()
    assert p.is_checksum_valid

def test_ip_parse_error_coverage():
    from unittest.mock import patch

    from pydivert.packet.ip import IPv4Header

    raw = bytearray(b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    p = Packet(raw)
    header = IPv4Header(p)

    with patch("socket.inet_ntop") as mock_ntop:
        mock_ntop.side_effect = ValueError("Mocked error")
        assert header.src_addr is None
        mock_ntop.assert_called_once()

def test_header_raw_setter_different_length():
    # Test line in header.py where it recalculates IP length
    raw = bytearray(
        b"\x45\x00\x00\x28" # IPv4 len 40
        b"\x00\x00\x00\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
        b"\x00\x50\x00\x51\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00"
    )
    p = Packet(raw)
    assert len(p.raw) == 40

    # Set TCP header to a different length (impossible in reality but tests the code)
    # We just want to trigger the branch in header.py:34 (approx)
    new_tcp = bytearray(b"\x00" * 30)
    assert p.tcp is not None
    p.tcp.raw = new_tcp
    assert len(p.raw) == 20 + 30
    assert p.ipv4 is not None
    assert p.ipv4.packet_len == 50
