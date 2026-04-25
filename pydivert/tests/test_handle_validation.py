import sys
from unittest.mock import MagicMock

import pytest

import pydivert
from pydivert import PyDivert
from pydivert.consts import Param


def _get_params():
    params = [
        ("recv", []),
        ("send", [MagicMock(spec=pydivert.Packet)]),
    ]
    if sys.platform == "win32":
        params.extend([
            ("recv_ex", []),
            ("send_ex", [MagicMock(spec=pydivert.Packet)]),
            ("get_param", [Param.QUEUE_LEN]),
            ("set_param", [Param.QUEUE_LEN, 1024]),
        ])
    return params

@pytest.mark.parametrize("method_name, args", _get_params())
def test_sync_methods_raise_without_open(method_name, args):
    w = PyDivert("false")
    method = getattr(w, method_name)
    with pytest.raises(RuntimeError) as excinfo:
        method(*args)
    assert "handle is not open" in str(excinfo.value) or "Queue is not open" in str(excinfo.value)


@pytest.mark.asyncio
async def test_recv_async_raises_without_open():
    w = PyDivert("false")
    with pytest.raises(RuntimeError) as excinfo:
        await w.recv_async()
    assert "handle is not open" in str(excinfo.value) or "Queue is not open" in str(excinfo.value)


@pytest.mark.asyncio
async def test_send_async_raises_without_open():
    w = PyDivert("false")
    packet = MagicMock(spec=pydivert.Packet)
    with pytest.raises(RuntimeError) as excinfo:
        await w.send_async(packet)
    assert "handle is not open" in str(excinfo.value) or "Queue is not open" in str(excinfo.value)
