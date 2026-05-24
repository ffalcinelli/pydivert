import asyncio

import pytest

import pydivert
from pydivert.packet import Packet


@pytest.mark.asyncio
async def test_recv_async_execution():
    try:
        async with pydivert.Divert("false") as w:
            try:
                await asyncio.wait_for(w.recv_async(), timeout=0.1)
            except (asyncio.TimeoutError, TimeoutError):
                pass
    except (PermissionError, OSError):
        pytest.skip("Test requires administrator/root privileges.")


@pytest.mark.asyncio
async def test_send_async_execution():
    try:
        async with pydivert.Divert("false") as w:
            # Create a dummy packet
            raw = bytearray(44)
            raw[0] = 0x45  # IPv4
            raw[9] = 6  # TCP
            p = Packet(raw)
            assert p.ipv4 is not None
            p.ipv4.packet_len = 44

            try:
                await w.send_async(p, recalculate_checksum=True)
            except Exception:
                pass
    except (PermissionError, OSError):
        pytest.skip("Test requires administrator/root privileges.")


@pytest.mark.asyncio
async def test_async_iterator_execution():
    try:
        async with pydivert.Divert("false") as w:
            # Trigger __aiter__
            it = w.__aiter__()
            assert it is w
            # Trigger __anext__
            try:
                await asyncio.wait_for(w.__anext__(), timeout=0.1)
            except (asyncio.TimeoutError, TimeoutError):
                pass
    except (PermissionError, OSError):
        pytest.skip("Test requires administrator/root privileges.")
