from pydivert.packet import Packet


def test_checksum_verification():
    # Mock a TCP packet
    raw = bytearray(44)
    raw[0] = 0x45  # IPv4
    raw[9] = 6  # TCP
    raw[12:16] = b"\x01\x02\x03\x04"  # src 1.2.3.4
    raw[16:20] = b"\x05\x06\x07\x08"  # dst 5.6.7.8
    raw[20:22] = b"\x00\x50"  # src port 80
    raw[22:24] = b"\x00\x51"  # dst port 81
    raw[32] = 0x50  # TCP header len 20 bytes
    raw[40:44] = b"PING"

    packet = Packet(raw)
    assert packet.ipv4 is not None
    packet.ipv4.packet_len = 44

    raw[10:12] = b"\x12\x34"  # Wrong IP checksum
    raw[36:38] = b"\x56\x78"  # Wrong TCP checksum

    # Initially invalid
    assert not packet.is_checksum_valid

    # Recalculate
    packet.recalculate_checksums()
    assert packet.is_checksum_valid

    # Corrupt a byte
    packet.ipv4.ttl = 64
    packet.recalculate_checksums()
    assert packet.is_checksum_valid

    packet.ipv4.ttl -= 1
    assert not packet.is_checksum_valid

    # Recalculate again
    packet.recalculate_checksums()
    assert packet.is_checksum_valid
