# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from unittest.mock import MagicMock

import pytest

import pydivert


def test_base_repr():
    with pydivert.Divert("false") as w:
        r = repr(w)
        assert "Divert" in r
        assert 'state="open"' in r
    assert 'state="closed"' in repr(w)


def test_base_iterator():
    with pydivert.Divert("false") as w:
        w._impl._recv_impl = MagicMock(side_effect=[pydivert.Packet(b"raw"), EOFError()])  # type: ignore
        packets = []
        for p in w:
            packets.append(p)
        assert len(packets) == 1


@pytest.mark.asyncio
async def test_base_async_iterator():
    async with pydivert.Divert("false") as w:

        async def mock_recv(*args, **kwargs):
            if not hasattr(mock_recv, "called"):
                mock_recv.called = True  # type: ignore
                return pydivert.Packet(b"raw")
            raise EOFError()

        w._impl._recv_async_impl = mock_recv  # type: ignore
        packets = []
        async for p in w:
            packets.append(p)
        assert len(packets) == 1


def test_base_recv_batch_jit():
    with pydivert.Divert("false") as w:
        p1 = pydivert.Packet(b"pkt1")
        p2 = pydivert.Packet(b"pkt2")
        w._impl._recv_batch_impl = MagicMock(return_value=[p1, p2])  # type: ignore

        # JIT filter that only accepts p1
        w._jit_filter = lambda p: p.raw == b"pkt1"

        packets = w.recv_batch(count=2)
        assert len(packets) == 1
        assert packets[0].raw == b"pkt1"


@pytest.mark.asyncio
async def test_base_recv_batch_async_jit():
    async with pydivert.Divert("false") as w:
        p1 = pydivert.Packet(b"pkt1")
        p2 = pydivert.Packet(b"pkt2")

        async def mock_recv_batch(*args, **kwargs):
            return [p1, p2]

        w._impl._recv_batch_async_impl = mock_recv_batch  # type: ignore

        # JIT filter that only accepts p2
        w._jit_filter = lambda p: p.raw == b"pkt2"

        packets = await w.recv_batch_async(count=2)
        assert len(packets) == 1
        assert packets[0].raw == b"pkt2"


def test_base_check_filter_static():
    # BaseDivert.check_filter is abstract but some backends might not override it?
    # Actually it is abstract in BaseDivert.
    assert pydivert.Divert.check_filter("true")[0]
