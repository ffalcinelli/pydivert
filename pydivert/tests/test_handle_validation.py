import sys
from unittest.mock import MagicMock

import pytest

import pydivert
from pydivert.consts import Param


@pytest.mark.parametrize(
    "method_name, args",
    [
        ("recv", []),
        pytest.param(
            "recv_ex",
            [],
            marks=pytest.mark.skipif(sys.platform != "win32", reason="recv_ex is Windows-only"),
        ),
        ("send", [MagicMock(spec=pydivert.Packet)]),
        pytest.param(
            "send_ex",
            [MagicMock(spec=pydivert.Packet)],
            marks=pytest.mark.skipif(sys.platform != "win32", reason="send_ex is Windows-only"),
        ),
        pytest.param(
            "get_param",
            [Param.QUEUE_LEN],
            marks=pytest.mark.skipif(sys.platform != "win32", reason="get_param is Windows-only"),
        ),
        pytest.param(
            "set_param",
            [Param.QUEUE_LEN, 1024],
            marks=pytest.mark.skipif(sys.platform != "win32", reason="set_param is Windows-only"),
        ),
    ],
)
def test_sync_methods_raise_without_open(method_name, args):
    w = pydivert.Divert("false")
    method = getattr(w, method_name)
    with pytest.raises(RuntimeError) as excinfo:
        method(*args)
    assert "Divert handle is not open" in str(excinfo.value)


@pytest.mark.asyncio
async def test_recv_async_raises_without_open():
    w = pydivert.Divert("false")
    with pytest.raises(RuntimeError) as excinfo:
        await w.recv_async()
    assert "Divert handle is not open" in str(excinfo.value)


@pytest.mark.asyncio
async def test_send_async_raises_without_open():
    w = pydivert.Divert("false")
    packet = MagicMock(spec=pydivert.Packet)
    with pytest.raises(RuntimeError) as excinfo:
        await w.send_async(packet)
    assert "Divert handle is not open" in str(excinfo.value)
