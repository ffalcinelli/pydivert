import socket
import pytest
import pydivert


def test_packet_checksum_real_ipv4_udp():
    # IPv4 + UDP packet
    raw = bytearray(
        b"\x45\x00\x00\x1c"  # IPv4, len 28
        b"\x00\x01\x00\x00"
        b"\x40\x11\x00\x00"  # TTL 64, Proto UDP, cksum 0 (to be recalculated)
        b"\x7f\x00\x00\x01"  # 127.0.0.1
        b"\x7f\x00\x00\x01"
        b"\x12\x34"  # SrcPort 4660
        b"\x12\x34"  # DstPort 4660
        b"\x00\x08\x00\x00"  # UDP Len 8, cksum 0 (to be recalculated)
    )
    p = pydivert.Packet(raw)

    # Recalculate to get valid checksums
    p.recalculate_checksums()
    assert p.ip_checksum is True
    assert p.udp_checksum is True
    assert p.is_checksum_valid is True

    # Corrupt IP checksum
    new_raw = bytearray(p.raw)
    new_raw[10] = (new_raw[10] + 1) % 256
    p.raw = new_raw
    assert p.ip_checksum is False
    assert p.is_checksum_valid is False

    # Recalculate
    p.recalculate_checksums()
    assert p.ip_checksum is True
    assert p.is_checksum_valid is True


def test_packet_checksum_real_ipv4_tcp():
    # IPv4 + TCP packet
    raw = bytearray(
        b"\x45\x00\x00\x28"  # IPv4, len 40
        b"\x00\x01\x00\x00"
        b"\x40\x06\x00\x00"  # TTL 64, Proto TCP, cksum 0
        b"\x7f\x00\x00\x01"  # 127.0.0.1
        b"\x7f\x00\x00\x01"
        b"\x12\x34"  # SrcPort 4660
        b"\x00\x50"  # DstPort 80
        b"\x00\x00\x00\x01"  # Seq
        b"\x00\x00\x00\x00"  # Ack
        b"\x50\x02\x20\x00"  # Flags, Window
        b"\x00\x00\x00\x00"  # cksum 0, urgent
    )
    p = pydivert.Packet(raw)
    p.recalculate_checksums()
    assert p.ip_checksum is True
    assert p.tcp_checksum is True
    assert p.is_checksum_valid is True

    # Corrupt TCP checksum
    new_raw = bytearray(p.raw)
    new_raw[36] = (new_raw[36] + 1) % 256
    p.raw = new_raw
    assert p.tcp_checksum is False
    assert p.is_checksum_valid is False

    # Recalculate
    p.recalculate_checksums()
    assert p.tcp_checksum is True
    assert p.is_checksum_valid is True


def test_packet_checksum_real_icmp():
    # IPv4 + ICMP Echo Request
    raw = bytearray(
        b"\x45\x00\x00\x1c"  # IPv4, len 28
        b"\x00\x01\x00\x00"
        b"\x40\x01\x00\x00"  # TTL 64, Proto ICMP, cksum 0
        b"\x7f\x00\x00\x01"  # 127.0.0.1
        b"\x7f\x00\x00\x01"
        b"\x08\x00\x00\x00"  # Type 8, Code 0, cksum 0
        b"\x12\x34\x00\x01"  # ID, Seq
    )
    p = pydivert.Packet(raw)
    p.recalculate_checksums()
    assert p.ip_checksum is True
    assert p.icmp_checksum is True
    assert p.is_checksum_valid is True

    # Corrupt ICMP
    new_raw = bytearray(p.raw)
    new_raw[22] = (new_raw[22] + 1) % 256
    p.raw = new_raw
    assert p.icmp_checksum is False
    assert p.is_checksum_valid is False

    # Recalculate
    p.recalculate_checksums()
    assert p.icmp_checksum is True
    assert p.is_checksum_valid is True


@pytest.mark.asyncio
async def test_packet_injection_recalculation_real():
    # Test that when we send a packet, checksums are automatically recalculated
    port = 55559
    addr = ("127.0.0.1", port)

    # Setup a listener
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(addr)
    server.settimeout(2.0)

    try:
        async with pydivert.Divert("false") as w:
            # Craft a simple UDP packet with WRONG checksums
            raw = bytearray(
                b"\x45\x00\x00\x20"  # IPv4, len 32
                b"\x00\x01\x00\x00"
                b"\x40\x11\x00\x00"  # cksum 0 (WRONG)
                b"\x7f\x00\x00\x01"
                b"\x7f\x00\x00\x01"
                b"\x12\x34"
                b"\xd9\x07"  # DstPort 55559
                b"\x00\x0c\x00\x00"  # cksum 0 (WRONG)
                b"data"
            )
            packet = pydivert.Packet(raw)
            # Individual properties should still report False if not recalculated
            assert packet.ip_checksum is False
            assert packet.udp_checksum is False

            # Send it - it should recalculate by default
            await w.send_async(packet)

            # Recalculated locally too
            assert packet.ip_checksum is True
            assert packet.udp_checksum is True

            data, _ = server.recvfrom(1024)
            assert data == b"data"
    finally:
        server.close()
