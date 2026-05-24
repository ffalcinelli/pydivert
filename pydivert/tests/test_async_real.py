import asyncio
import socket

import pytest

import pydivert


@pytest.mark.asyncio
async def test_recv_async_real():
    # Use a high port to avoid conflicts
    port = 55555
    addr = ("127.0.0.1", port)

    with pydivert.Divert(f"udp.DstPort == {port}") as w:
        # Start a task to receive the packet
        recv_task = asyncio.create_task(w.recv_async())

        # Give some time for the task to start
        await asyncio.sleep(0.1)

        # Send a packet via regular socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"hello-async", addr)

        # Wait for the packet
        packet = await asyncio.wait_for(recv_task, timeout=2.0)

        assert packet.payload == b"hello-async"
        assert packet.udp is not None
        assert packet.udp.dst_port == port


@pytest.mark.asyncio
async def test_send_async_real():
    port = 55556
    addr = ("127.0.0.1", port)

    # Setup a listener
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(addr)
    server.settimeout(2.0)

    try:
        async with pydivert.Divert("false") as w:
            # Craft a simple UDP packet
            # IPv4(20) + UDP(8) + "data"(4) = 32 bytes
            raw = bytearray(
                b"\x45\x00\x00\x20"  # IPv4, len 32
                b"\x00\x01\x00\x00"
                b"\x40\x11\x00\x00"  # TTL 64, Proto UDP, cksum 0
                b"\x7f\x00\x00\x01"  # 127.0.0.1
                b"\x7f\x00\x00\x01"
                b"\x12\x34"  # SrcPort 4660
                b"\xd9\x04"  # DstPort 55556
                b"\x00\x0c\x00\x00"  # UDP Len 12 (8+4), cksum 0
                b"data"
            )
            packet = pydivert.Packet(raw)
            packet.recalculate_checksums()

            # Send it async
            sent_len = await w.send_async(packet)
            assert sent_len > 0

            # Try to receive on server (using thread because sock_recvfrom is tricky for raw sockets/local)
            # Actually, standard recvfrom should work for UDP.
            data, _ = server.recvfrom(1024)
            assert data == b"data"
    finally:
        server.close()


@pytest.mark.asyncio
async def test_recv_async_cancellation_real():
    port = 55557
    with pydivert.Divert(f"udp.DstPort == {port}") as w:
        recv_task = asyncio.create_task(w.recv_async())
        await asyncio.sleep(0.1)
        recv_task.cancel()
        try:
            await recv_task
        except asyncio.CancelledError:
            pass
        # Verification that it was indeed cancelled
        assert recv_task.cancelled()


@pytest.mark.asyncio
async def test_recv_batch_async_real():
    port = 55558
    addr = ("127.0.0.1", port)

    with pydivert.Divert(f"udp.DstPort == {port}") as w:
        # Send 3 packets
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for i in range(3):
                sock.sendto(f"batch-{i}".encode(), addr)

        # Give the driver a moment to queue all packets
        await asyncio.sleep(0.1)

        # Receive them in batch
        packets = await asyncio.wait_for(w.recv_batch_async(count=3), timeout=2.0)
        assert len(packets) == 3
        assert packets[0].payload == b"batch-0"
        assert packets[1].payload == b"batch-1"
        assert packets[2].payload == b"batch-2"
