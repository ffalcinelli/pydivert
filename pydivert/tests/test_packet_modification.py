# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import pydivert


def test_payload_modification_different_length():
    # Create a dummy UDP packet manually for testing
    # IPv4 (20 bytes) + UDP (8 bytes) + Payload (3 bytes "abc")
    # Total 31 bytes
    raw_packet = bytearray([
        0x45, 0x00, 0x00, 0x1f, # IPv4, Len=31
        0x00, 0x00, 0x40, 0x00, # Ident=0, Flags/Frag=0x4000 (DF)
        0x40, 0x11, 0x00, 0x00, # TTL=64, Proto=UDP(17), Checksum=0 (placeholder)
        127, 0, 0, 1,           # Src=127.0.0.1
        127, 0, 0, 1,           # Dst=127.0.0.1
        0x12, 0x34, 0x00, 0x50, # SrcPort=4660, DstPort=80
        0x00, 0x0b, 0x00, 0x00, # UDP Len=11 (8+3), Checksum=0
        0x61, 0x62, 0x63        # Payload "abc"
    ])

    # We use bytearray to verify our fix that handles bytearray in Packet constructor
    packet = pydivert.Packet(raw_packet)

    assert packet.payload == b"abc"
    assert len(packet.raw) == 31
    assert packet.ipv4.packet_len == 31
    assert packet.udp.payload_len == 3

    # Modify payload to something longer
    packet.payload = b"defgh" # 5 bytes

    assert packet.payload == b"defgh"
    assert len(packet.raw) == 33
    assert packet.ipv4.packet_len == 33
    assert packet.udp.payload_len == 5

    # Verify that changing payload updated the raw data
    assert packet.raw[-5:] == b"defgh"
