from unittest.mock import MagicMock

import pytest

import pydivert
from pydivert.consts import Param
from pydivert.windivert import WinDivert


@pytest.mark.parametrize("method_name, args", [
    ("recv", []),
    ("recv_ex", []),
    ("send", [MagicMock(spec=pydivert.Packet)]),
    ("send_ex", [MagicMock(spec=pydivert.Packet)]),
    ("get_param", [Param.QUEUE_LEN]),
    ("set_param", [Param.QUEUE_LEN, 1024]),
])
def test_sync_methods_raise_without_open(method_name, args):
    w = WinDivert("false")
    method = getattr(w, method_name)
    with pytest.raises(RuntimeError) as excinfo:
        method(*args)
    assert "WinDivert handle is not open" in str(excinfo.value)


@pytest.mark.asyncio
async def test_recv_async_raises_without_open():
    w = WinDivert("false")
    with pytest.raises(RuntimeError) as excinfo:
        await w.recv_async()
    assert "WinDivert handle is not open" in str(excinfo.value)


@pytest.mark.asyncio
async def test_send_async_raises_without_open():
    w = WinDivert("false")
    packet = MagicMock(spec=pydivert.Packet)
    with pytest.raises(RuntimeError) as excinfo:
        await w.send_async(packet)
    assert "WinDivert handle is not open" in str(excinfo.value)
