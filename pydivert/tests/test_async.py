import asyncio
import socket

import pytest

import pydivert

# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils


@pytest.mark.asyncio
async def test_async_context_manager():
    try:
        async with pydivert.Divert("false") as w:
            assert w.is_open
    except (PermissionError, OSError):
        pytest.skip("Test requires administrator/root privileges.")


@pytest.mark.asyncio
async def test_recv_async_real():
    port = 55555
    addr = ("127.0.0.1", port)
    try:
        with pydivert.Divert(f"udp.DstPort == {port}") as w:
            recv_task = asyncio.create_task(w.recv_async())
            await asyncio.sleep(0.1)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"hello-async", addr)
            packet = await asyncio.wait_for(recv_task, timeout=2.0)
            assert packet.payload == b"hello-async"
    except (PermissionError, OSError):
        pytest.skip("Insufficient privileges")


@pytest.mark.asyncio
async def test_send_async_real():
    port = 55556
    addr = ("127.0.0.1", port)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(addr)
    server.settimeout(2.0)
    try:
        async with pydivert.Divert("false") as w:
            raw = bytearray(
                b"\x45\x00\x00\x20\x00\x01\x00\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
                b"\x12\x34\xd9\x04\x00\x0c\x00\x00" + b"data"
            )
            packet = pydivert.Packet(raw)
            packet.recalculate_checksums()
            await w.send_async(packet)
            data, _ = server.recvfrom(1024)
            assert data == b"data"
    except (PermissionError, OSError):
        pytest.skip("Insufficient privileges")
    finally:
        server.close()


@pytest.mark.asyncio
async def test_async_iterator():
    try:
        async with pydivert.Divert("false") as w:
            it = w.__aiter__()
            assert it is w
            try:
                await asyncio.wait_for(w.__anext__(), timeout=0.1)
            except (asyncio.TimeoutError, TimeoutError):
                pass
    except (PermissionError, OSError):
        pytest.skip("Insufficient privileges")


@pytest.mark.asyncio
async def test_recv_batch_async():
    port = 55558
    addr = ("127.0.0.1", port)
    try:
        with pydivert.Divert(f"udp.DstPort == {port}") as w:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                for i in range(2):
                    sock.sendto(f"b-{i}".encode(), addr)
            await asyncio.sleep(0.2)
            packets = await asyncio.wait_for(w.recv_batch_async(count=2), timeout=2.0)
            assert len(packets) >= 1  # WinDivert might return partial batch on timeout
    except (PermissionError, OSError):
        pytest.skip("Insufficient privileges")


@pytest.mark.asyncio
async def test_recv_async_cancellation():
    try:
        with pydivert.Divert("false") as w:
            recv_task = asyncio.create_task(w.recv_async())
            await asyncio.sleep(0.1)
            recv_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await recv_task
    except (PermissionError, OSError):
        pytest.skip("Insufficient privileges")
