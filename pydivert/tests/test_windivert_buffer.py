import ctypes
from unittest.mock import patch

from pydivert import WinDivert


class MockOverlapped:
    pass


@patch("pydivert.windivert.byref", lambda x: x)
@patch("pydivert.windivert.windivert_dll")
def test_windivert_recv_buffer_reuse(wd_dll):
    w = WinDivert()
    w._handle = "fake_handle"

    # We don't care about address internal contents as long as parse_packet doesn't crash,
    # but let's mock the class to return an object with correct fields.
    class MockAddrNetwork:
        IfIdx = 0
        SubIfIdx = 0

    class MockAddress:
        Network = MockAddrNetwork()
        Outbound = 1
        Timestamp = 0
        Loopback = 0
        Impostor = 0
        Sniffed = 0
        IPChecksum = 0
        TCPChecksum = 0
        UDPChecksum = 0
        Layer = 0
        Event = 0
        Flow = 0
        Socket = 0
        Reflect = 0

    wd_dll.WinDivertAddress.return_value = MockAddress()

    def fake_recv(handle, pPacket, packetLen, pRecvLen, pAddr):
        # pRecvLen here will just be the c_uint directly since we mocked byref
        pRecvLen.value = 5
        ctypes.memmove(pPacket, b"hello", 5)

    wd_dll.WinDivertRecv.side_effect = fake_recv

    packet1 = w.recv()
    assert packet1.raw.tobytes() == b"hello"

    def fake_recv2(handle, pPacket, packetLen, pRecvLen, pAddr):
        pRecvLen.value = 6
        ctypes.memmove(pPacket, b"world!", 6)

    wd_dll.WinDivertRecv.side_effect = fake_recv2

    packet2 = w.recv()
    assert packet2.raw.tobytes() == b"world!"

    # Original packet should not be overwritten
    assert packet1.raw.tobytes() == b"hello"


@patch("pydivert.windivert.byref", lambda x: x)
@patch("pydivert.windivert.windivert_dll")
def test_windivert_recv_ex_buffer_reuse(wd_dll):
    w = WinDivert()
    w._handle = "fake_handle"

    class MockAddrNetwork:
        IfIdx = 0
        SubIfIdx = 0

    class MockAddress:
        Network = MockAddrNetwork()
        Outbound = 1
        Timestamp = 0
        Loopback = 0
        Impostor = 0
        Sniffed = 0
        IPChecksum = 0
        TCPChecksum = 0
        UDPChecksum = 0
        Layer = 0
        Event = 0
        Flow = 0
        Socket = 0
        Reflect = 0

    wd_dll.WinDivertAddress.return_value = MockAddress()

    def fake_recv_ex(handle, pPacket, packetLen, pRecvLen, flags, pAddr, pAddrLen, overlapped):
        pRecvLen.value = 5
        ctypes.memmove(pPacket, b"hello", 5)

    wd_dll.WinDivertRecvEx.side_effect = fake_recv_ex

    packet1 = w.recv_ex()
    assert packet1.raw.tobytes() == b"hello"

    def fake_recv_ex2(handle, pPacket, packetLen, pRecvLen, flags, pAddr, pAddrLen, overlapped):
        pRecvLen.value = 6
        ctypes.memmove(pPacket, b"world!", 6)

    wd_dll.WinDivertRecvEx.side_effect = fake_recv_ex2

    packet2 = w.recv_ex()
    assert packet2.raw.tobytes() == b"world!"

    # Original packet should not be overwritten
    assert packet1.raw.tobytes() == b"hello"

    overlap = MockOverlapped()
    packet3 = w.recv_ex(overlapped=overlap)
    assert packet3.raw.tobytes() == b"world!"
