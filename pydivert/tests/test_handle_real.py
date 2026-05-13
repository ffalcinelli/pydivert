import pytest

import pydivert
from pydivert.packet import Packet


def test_recv_closed_handle_real():
    w = pydivert.Divert("false")
    w.open()
    w.close()
    with pytest.raises(RuntimeError, match="Divert handle is not open"):
        w.recv()


def test_send_closed_handle_real():
    w = pydivert.Divert("false")
    w.open()
    w.close()
    p = Packet(bytearray(20))
    with pytest.raises(RuntimeError, match="Divert handle is not open"):
        w.send(p)


def test_stats_closed_handle_real():
    w = pydivert.Divert("false")
    w.open()
    w.close()
    with pytest.raises(RuntimeError, match="Divert handle is not open"):
        w.stats()


@pytest.mark.asyncio
async def test_async_closed_handle_real():
    w = pydivert.Divert("false")
    w.open()
    w.close()
    with pytest.raises(RuntimeError, match="Divert handle is not open"):
        await w.recv_async()
    with pytest.raises(RuntimeError, match="Divert handle is not open"):
        await w.send_async(Packet(bytearray(20)))


def test_double_open_real():
    with pydivert.Divert("false") as w:
        with pytest.raises(RuntimeError, match="Divert handle is already open"):
            w.open()


def test_double_close_real():
    w = pydivert.Divert("false")
    w.open()
    w.close()
    with pytest.raises(RuntimeError, match="Divert handle is not open"):
        w.close()
