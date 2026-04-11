import ctypes
import sys
from unittest.mock import patch

import pytest

from pydivert import WinDivert

pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason="Windows only")


class MockOverlapped:
    pass


@patch("pydivert.windivert.byref", lambda x: x)
@patch("pydivert.windivert.windivert_dll")
def test_windivert_recv_buffer_reuse(wd_dll):
    w = WinDivert()
    w._handle = "fake_handle"

    def fake_recv(handle, pPacket, packetLen, pRecvLen, pAddr):
        # pRecvLen here will just be the c_uint directly since we mocked byref
        pRecvLen.value = 5
        ctypes.memmove(pPacket, b"hello", 5)
        pAddr.Outbound = 1

    wd_dll.WinDivertRecv.side_effect = fake_recv

    packet1 = w.recv()
    assert packet1.raw.tobytes() == b"hello"

    def fake_recv2(handle, pPacket, packetLen, pRecvLen, pAddr):
        pRecvLen.value = 6
        ctypes.memmove(pPacket, b"world!", 6)
        pAddr.Outbound = 1

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

    def fake_recv_ex(handle, pPacket, packetLen, pRecvLen, flags, pAddr, pAddrLen, overlapped):
        pRecvLen.value = 5
        ctypes.memmove(pPacket, b"hello", 5)
        pAddr.Outbound = 1

    wd_dll.WinDivertRecvEx.side_effect = fake_recv_ex

    packet1 = w.recv_ex()
    assert packet1.raw.tobytes() == b"hello"

    def fake_recv_ex2(handle, pPacket, packetLen, pRecvLen, flags, pAddr, pAddrLen, overlapped):
        pRecvLen.value = 6
        ctypes.memmove(pPacket, b"world!", 6)
        pAddr.Outbound = 1

    wd_dll.WinDivertRecvEx.side_effect = fake_recv_ex2

    packet2 = w.recv_ex()
    assert packet2.raw.tobytes() == b"world!"

    # Original packet should not be overwritten
    assert packet1.raw.tobytes() == b"hello"

    overlap = MockOverlapped()
    packet3 = w.recv_ex(overlapped=overlap)
    assert packet3.raw.tobytes() == b"world!"
