# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import pytest
from pydivert.base import BaseDivert
from pydivert.consts import Flag, Layer
from pydivert.packet import Packet

class MockBackend(BaseDivert):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.open_called = False
        self.close_called = False
        self.recv_called = False
        self.send_called = False

    def _open_impl(self):
        self.open_called = True

    def _close_impl(self):
        self.close_called = True

    def _recv_impl(self, bufsize, timeout):
        self.recv_called = True
        return Packet(b"E" + b"\x00" * 19)

    def _recv_batch_impl(self, count, bufsize, timeout):
        return [self._recv_impl(bufsize, timeout) for _ in range(count)]

    async def _recv_async_impl(self, bufsize, timeout):
        return self._recv_impl(bufsize, timeout)

    async def _recv_batch_async_impl(self, count, bufsize, timeout):
        return self._recv_batch_impl(count, bufsize, timeout)

    def _stats_impl(self):
        return {"diverted": 0, "dropped": 0, "sniffed": 0}

    def _send_impl(self, packet, recalculate_checksum):
        self.send_called = True
        return len(packet.raw)

    async def _send_async_impl(self, packet, recalculate_checksum):
        return self._send_impl(packet, recalculate_checksum)


def test_base_state_management():
    w = MockBackend()
    assert not w.is_open

    # Cannot recv when closed
    with pytest.raises(RuntimeError, match="not open"):
        w.recv()

    # Cannot send when closed
    p = Packet(b"E" + b"\x00" * 19)
    with pytest.raises(RuntimeError, match="not open"):
        w.send(p)

    w.open()
    assert w.is_open
    assert w.open_called

    # Cannot open when open
    with pytest.raises(RuntimeError, match="already open"):
        w.open()

    w.recv()
    assert w.recv_called

    w.send(p)
    assert w.send_called

    w.close()
    assert not w.is_open
    assert w.close_called

    # Cannot close when closed
    with pytest.raises(RuntimeError, match="not open"):
        w.close()

def test_base_properties():
    w = MockBackend(filter="tcp", layer=Layer.NETWORK, priority=100, flags=Flag.SNIFF)
    assert w.filter == "tcp"
    assert w.layer == Layer.NETWORK
    assert w.priority == 100
    assert w.flags == Flag.SNIFF

@pytest.mark.asyncio
async def test_base_async_state_management():
    w = MockBackend()
    p = Packet(b"E" + b"\x00" * 19)
    
    with pytest.raises(RuntimeError, match="not open"):
        await w.recv_async()
    
    with pytest.raises(RuntimeError, match="not open"):
        await w.send_async(p)
    
    async with w:
        assert w.is_open
        await w.recv_async()
        await w.send_async(p)
    
    assert not w.is_open
