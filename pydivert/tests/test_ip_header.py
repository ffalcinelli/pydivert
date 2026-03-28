import pytest

from pydivert.packet.ip import IPHeader


def test_ip_header_packet_len_setter():
    class DummyPacket:
        def __init__(self):
            self.raw = memoryview(bytearray(b"dummy"))

    ip_header = IPHeader(DummyPacket())
    with pytest.raises(AttributeError, match="can't set attribute"):
        ip_header.packet_len = 100
