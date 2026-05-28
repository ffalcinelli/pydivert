# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later

import pydivert


def test_tcp_properties_and_flags():
    """
    Integration test for all TCP header properties and flags to ensure 100% coverage of pydivert/packet/tcp.py.
    """
    # Minimal setup to avoid scenario fixture conflicts
    with pydivert.Divert("tcp", interfaces=["lo"]) as w:
        # Create a dummy TCP packet
        raw = (
            b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
            + b"\x00\x50\x1f\x90\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x91\x7c\x00\x00"
        )
        packet = pydivert.Packet(raw)
        assert packet.tcp is not None

        # Test flags
        flags = ["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr", "ns"]
        for flag in flags:
            setattr(packet.tcp, flag, True)
            assert getattr(packet.tcp, flag) is True
            setattr(packet.tcp, flag, False)
            assert getattr(packet.tcp, flag) is False

        # Test numeric fields
        packet.tcp.seq_num = 12345678
        assert packet.tcp.seq_num == 12345678

        packet.tcp.ack_num = 87654321
        assert packet.tcp.ack_num == 87654321

        packet.tcp.window = 65535
        assert packet.tcp.window == 65535

        packet.tcp.urg_ptr = 10
        assert packet.tcp.urg_ptr == 10

        packet.tcp.reserved = 5
        assert packet.tcp.reserved == 5

        packet.tcp.data_offset = 8
        assert packet.tcp.data_offset == 8
        assert packet.tcp.header_len == 32

        # Test control_bits
        packet.tcp.control_bits = 0x1FF
        assert packet.tcp.control_bits == 0x1FF
        assert packet.tcp.fin is True
        assert packet.tcp.ns is True

        # Test checksum setter
        packet.tcp.cksum = 0xABCD
        assert packet.tcp.cksum == 0xABCD

        # Ensure reinjection works (dry run or lo)
        packet.dst_addr = "127.0.0.1"
        w.send(packet)


def test_tcp_ipv6_payload_len():
    """
    Test TCP payload_len property on IPv6 packets.
    """
    # Dummy IPv6 TCP packet
    raw = (
        b"\x60\x00\x00\x00\x00\x14\x06\x40"
        + b"\x00" * 16
        + b"\x00" * 15
        + b"\x01"
        + b"\x00\x50\x1f\x90\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x91\x7c\x00\x00"
    )
    packet = pydivert.Packet(raw)
    assert packet.ipv6 is not None
    assert packet.tcp is not None
    # IPv6 payload_len is 20, TCP header is 20, so TCP payload is 0 in this dummy
    assert packet.tcp.payload_len == 0

    # Add some payload
    packet.raw = packet.raw.tobytes() + b"payload"
    # Need to update IPv6 payload_len manually or via recalculate_checksums?
    # Actually payload_len property uses packet.raw length for IPv6 fallback or packet.ipv6.payload_len
    packet.ipv6.payload_len = 27  # 20 (tcp) + 7 (payload)
    assert packet.tcp.payload_len == 7
