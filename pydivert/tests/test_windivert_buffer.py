import ctypes
import sys
from typing import Any, cast
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
        # Handle both direct c_uint and CArgObject
        if hasattr(pRecvLen, "value"):
            pRecvLen.value = 5
        else:
            # Fallback if byref wasn't successfully mocked to return the object
            ctypes.cast(pRecvLen, ctypes.POINTER(ctypes.c_uint)).contents.value = 5

        ctypes.memmove(pPacket, b"hello", 5)

        if hasattr(pAddr, "Outbound"):
            pAddr.Outbound = 1
        else:
            # WinDivertAddress is more complex to cast, hope byref mock works
            pass

    wd_dll.WinDivertRecv.side_effect = fake_recv

    packet1 = w.recv()
    assert packet1 is not None
    assert packet1.raw.tobytes() == b"hello"

    def fake_recv2(handle, pPacket, packetLen, pRecvLen, pAddr):
        pRecvLen.value = 6
        ctypes.memmove(pPacket, b"world!", 6)
        pAddr.Outbound = 1

    wd_dll.WinDivertRecv.side_effect = fake_recv2

    packet2 = w.recv()
    assert packet2 is not None
    assert packet2.raw.tobytes() == b"world!"

    # Original packet should not be overwritten
    assert packet1 is not None
    assert packet1.raw.tobytes() == b"hello"


@patch("pydivert.windivert.byref", lambda x: x)
@patch("pydivert.windivert.windivert_dll")
def test_windivert_recv_ex_buffer_reuse(wd_dll):
    w = WinDivert()
    w._handle = "fake_handle"

    def fake_recv_ex(handle, pPacket, packetLen, pRecvLen, flags, pAddr, pAddrLen, overlapped):
        if hasattr(pRecvLen, "value"):
            pRecvLen.value = 5
        else:
            ctypes.cast(pRecvLen, ctypes.POINTER(ctypes.c_uint)).contents.value = 5

        ctypes.memmove(pPacket, b"hello", 5)

        if hasattr(pAddr, "Outbound"):
            pAddr.Outbound = 1

    wd_dll.WinDivertRecvEx.side_effect = fake_recv_ex

    packet1 = w.recv_ex()
    assert packet1 is not None
    assert packet1.raw.tobytes() == b"hello"

    def fake_recv_ex2(handle, pPacket, packetLen, pRecvLen, flags, pAddr, pAddrLen, overlapped):
        pRecvLen.value = 6
        ctypes.memmove(pPacket, b"world!", 6)
        pAddr.Outbound = 1

    wd_dll.WinDivertRecvEx.side_effect = fake_recv_ex2

    packet2 = w.recv_ex()
    assert packet2 is not None
    assert packet2.raw.tobytes() == b"world!"

    # Original packet should not be overwritten
    assert packet1 is not None
    assert packet1.raw.tobytes() == b"hello"

    overlap = MockOverlapped()
    packet3 = w.recv_ex(overlapped=cast(Any, overlap))
    assert packet3 is not None
    assert packet3.raw.tobytes() == b"world!"
