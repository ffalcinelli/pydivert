from pydivert.packet import Packet
from pydivert.packet.ip import IPv4Header
from pydivert.packet.tcp import TCPHeader


def test_pattern_matching_packet():
    # Mock a TCP packet
    # 20 bytes IPv4 + 20 bytes TCP
    raw = bytearray(40)
    raw[0] = 0x45 # IPv4
    raw[9] = 6 # TCP
    raw[12:16] = b"\x01\x02\x03\x04" # src 1.2.3.4
    raw[22:24] = b"\x00\x50" # dst port 80

    packet = Packet(raw)

    match packet:
        case Packet(tcp=TCPHeader(dst_port=80), ipv4=IPv4Header(src_addr="1.2.3.4")):
            matched = True
        case _:
            matched = False

    assert matched

def test_pattern_matching_udp():
    raw = bytearray(28)
    raw[0] = 0x45
    raw[9] = 17 # UDP
    packet = Packet(raw)

    match packet:
        case Packet(udp=_):
            matched = True
        case _:
            matched = False
    assert matched
