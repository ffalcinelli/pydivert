# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
import asyncio
import os
import socket
import sys
import threading
import time

import pytest

import pydivert


def setup_module(module):
    """Skip all tests in this module if PyDivert cannot be initialized."""
    try:
        with pydivert.PyDivert("true"):
            pass
    except (ImportError, PermissionError, OSError, RuntimeError) as e:
        if os.environ.get("GITHUB_ACTIONS"):
            if sys.platform == "darwin" and getattr(e, "errno", None) == 22:
                pytest.skip(f"Divert sockets are not supported on this macOS version: {e}")
            pytest.fail(f"PyDivert integration tests must run in CI, but initialization failed: {e}")
        pytest.skip(f"PyDivert not available: {e}")


def get_free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run_icmp_modifier(stop_event, use_async):
    # Intercept ICMP Echo Replies (Type 0)
    filt = "icmp.Type == 0"
    if use_async:
        async def run_async():
            async with pydivert.PyDivert(filt) as w:
                async for packet in w:
                    if packet.icmp:
                        # Append some data to the ICMP payload if possible
                        # Or just modify existing payload
                        if packet.payload:
                            packet.payload = packet.payload.replace(b"abc", b"xyz")
                    await w.send_async(packet)
                    if stop_event.is_set():
                        break
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_async())
    else:
        with pydivert.PyDivert(filt) as w:
            for packet in w:
                if packet.icmp and packet.payload:
                    packet.payload = packet.payload.replace(b"abc", b"xyz")
                w.send(packet)
                if stop_event.is_set():
                    break


@pytest.mark.parametrize("use_async", [False, True])
def test_icmp_echo_reply_modification(use_async):
    """
    Scenario: Intercept ICMP Echo Replies and modify the payload data.
    """
    # Note: Sending ICMP packets often requires root/admin itself
    stop_event = threading.Event()
    divert_thread = threading.Thread(target=_run_icmp_modifier, args=(stop_event, use_async), daemon=True)
    divert_thread.start()
    time.sleep(2.0)

    try:
        from scapy.all import conf, sr1
        from scapy.layers.inet import ICMP, IP
        _ = conf.L3socket  # Force scapy init

        # We send an ICMP Echo Request with "abc" in payload
        # The OS will respond with Echo Reply containing "abc"
        # PyDivert should change it to "xyz"
        pkt = IP(dst="127.0.0.1")/ICMP(type=8)/b"abc"
        reply = sr1(pkt, timeout=5, verbose=False)

        if reply and ICMP in reply:
             # Type 0 is Echo Reply
             if reply[ICMP].type == 0:
                 assert b"xyz" in bytes(reply[ICMP].payload)
             else:
                 pytest.skip(f"Received unexpected ICMP type: {reply[ICMP].type}")
        else:
             pytest.skip("No ICMP reply received (blocked by firewall or OS?)")
    except ImportError:
        pytest.skip("Scapy not installed, skipping ICMP test")
    except PermissionError:
        pytest.skip("Insufficient permissions to send raw ICMP packets")
    finally:
        stop_event.set()
        # Unblock by sending one last ICMP (though it might not match)
        divert_thread.join(timeout=1)


def _run_tcp_throttler(port, stop_event, use_async):
    # Intercept TCP traffic to a specific port
    filt = f"tcp.DstPort == {port}"
    if use_async:
        async def run_async():
            async with pydivert.PyDivert(filt) as w:
                async for packet in w:
                    # Delay sending the packet to simulate high latency/throttling
                    await asyncio.sleep(0.5)
                    await w.send_async(packet)
                    if stop_event.is_set():
                        break
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_async())
    else:
        with pydivert.PyDivert(filt) as w:
            for packet in w:
                time.sleep(0.5)
                w.send(packet)
                if stop_event.is_set():
                    break


@pytest.mark.parametrize("use_async", [False, True])
def test_tcp_latency_simulation(use_async):
    """
    Scenario: Simulate network latency by delaying TCP packets to a specific port.
    """
    port = get_free_port()

    def server():
        with socket.socket() as s:
            s.bind(("127.0.0.1", port))
            s.listen(1)
            try:
                conn, _ = s.accept()
                data = conn.recv(1024)
                conn.sendall(data)
                conn.close()
            except Exception:
                pass

    server_thread = threading.Thread(target=server, daemon=True)
    server_thread.start()

    stop_event = threading.Event()
    divert_thread = threading.Thread(target=_run_tcp_throttler, args=(port, stop_event, use_async), daemon=True)
    divert_thread.start()
    time.sleep(2.0)

    try:
        start_time = time.time()
        with socket.create_connection(("127.0.0.1", port), timeout=10) as client:
            client.sendall(b"ping")
            resp = client.recv(1024)
            assert resp == b"ping"
        end_time = time.time()

        # Each TCP packet (SYN, Data, FIN) will be delayed by 0.5s.
        # Expecting at least 1.0s total time.
        duration = end_time - start_time
        assert duration >= 1.0
    finally:
        stop_event.set()
        try:
             socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except Exception:
             pass
        divert_thread.join(timeout=1)
