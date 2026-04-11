# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later

import pytest

from pydivert.base import BaseDivert
from pydivert.consts import Flag, Layer


class MockDivert(BaseDivert):
    def __init__(self, filter="true", layer=Layer.NETWORK, priority=0, flags=Flag.DEFAULT):
        super().__init__(filter, layer, priority, flags)
        self._is_open = False
        self._counter = 0

    def open(self): self._is_open = True
    def close(self): self._is_open = False
    @property
    def is_open(self): return self._is_open

    def recv(self):
        if self._counter > 0:
            raise StopIteration
        self._counter += 1
        return MagicPacket()

    async def recv_async(self):
        if self._counter > 0:
            raise StopAsyncIteration
        self._counter += 1
        return MagicPacket()

    def send(self, packet, recalculate_checksum=True): return 0
    async def send_async(self, packet, recalculate_checksum=True): return 0

class MagicPacket:
    raw = b"data"

def test_base_properties():
    d = MockDivert("tcp.DstPort == 80", Layer.FLOW, 10, Flag.SNIFF)
    assert d.filter == "tcp.DstPort == 80"
    assert d.layer == Layer.FLOW
    assert d.priority == 10
    assert d.flags == Flag.SNIFF

def test_base_context_manager():
    d = MockDivert()
    with d as opened:
        assert opened.is_open
        assert d.is_open
    assert not d.is_open

@pytest.mark.asyncio
async def test_base_async_context_manager():
    d = MockDivert()
    async with d as opened:
        assert opened.is_open
        assert d.is_open
    assert not d.is_open

def test_base_iteration():
    d = MockDivert()
    it = iter(d)
    assert it == d
    for p in d:
        assert isinstance(p, MagicPacket)

@pytest.mark.asyncio
async def test_base_async_iteration():
    d = MockDivert()
    ait = d.__aiter__()
    assert ait == d
    async for p in d:
        assert isinstance(p, MagicPacket)
