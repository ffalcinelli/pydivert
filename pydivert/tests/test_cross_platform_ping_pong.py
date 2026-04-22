# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import socket
import sys
import threading
import time

import pytest

from pydivert import PyDivert


def setup_module(module):
    """Skip all tests in this module if PyDivert cannot be initialized.
    Requires Administrator (Windows) or Root (Linux/BSD) privileges.
    """
    import os
    try:
        with PyDivert("true"):
            pass
    except (ImportError, PermissionError, OSError, RuntimeError) as e:
        if os.environ.get("GITHUB_ACTIONS"):
            if sys.platform == "darwin" and getattr(e, "errno", None) == 22:
                pytest.skip(f"Divert sockets are not supported on this macOS version: {e}")
            else:
                pytest.fail(f"PyDivert integration tests must run in CI, but initialization failed: {e}")
        pytest.skip(f"PyDivert not available: {e}. Are you running as Administrator/Root?")


def get_free_port(proto=socket.SOCK_DGRAM):
    with socket.socket(socket.AF_INET, proto) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def udp_echo_server(port, stop_event):
    """
    Simple UDP echo server that prepends 'Echo: ' to the received data.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", port))
        s.settimeout(0.5)
        while not stop_event.is_set():
            try:
                data, addr = s.recvfrom(1024)
                # Echo 'STOP' back so the diverter catches it and exits
                if data == b"STOP":
                    s.sendto(b"Echo: STOP", addr)
                    break
                s.sendto(b"Echo: " + data, addr)
            except TimeoutError:
                continue
            except Exception:
                break


def _run_diverter(filter_str, stop_event, captured_count):
    try:
        print(f"Diverter starting with filter: {filter_str}")
        with PyDivert(filter_str) as w:
            print("Diverter opened successfully")
            while not stop_event.is_set():
                try:
                    packet = w.recv()
                    print(f"Captured packet: {packet}")
                    captured_count[0] += 1
                    if packet.payload and b"Echo: " in packet.payload:
                        packet.payload = packet.payload.replace(b"Echo: ", b"Modified: ")
                    w.send(packet)
                except Exception as e:
                    if not stop_event.is_set():
                        print(f"Diverter error: {e}")
                    break
        print("Diverter closed")
    except (PermissionError, OSError) as e:
        print(f"Failed to open PyDivert: {e}")


async def _run_diverter_async(filter_str, stop_event, captured_count):
    import asyncio
    try:
        print(f"Async Diverter starting with filter: {filter_str}")
        async with PyDivert(filter_str) as w:
            print("Async Diverter opened successfully")
            while not stop_event.is_set():
                try:
                    packet = await asyncio.wait_for(w.recv_async(), timeout=10.0)
                    print(f"Async Captured packet: {packet}")
                    captured_count[0] += 1
                    if packet.payload and b"Echo: " in packet.payload:
                        packet.payload = packet.payload.replace(b"Echo: ", b"Modified: ")
                    await w.send_async(packet)
                except asyncio.TimeoutError:
                    print("Async Diverter wait_for timeout")
                    continue
                except Exception as e:
                    if not stop_event.is_set():
                        print(f"Diverter async error: {e}")
                    break
        print("Async Diverter closed")
    except (PermissionError, OSError) as e:
        print(f"Failed to open PyDivert Async: {e}")


@pytest.mark.parametrize("use_async", [False, True])
def test_ping_pong_modification(use_async):
    """
    Cross-platform Ping-Pong test:
    1. Start a UDP Echo Server.
    2. Intercept the echo response using PyDivert.
    3. Modify the payload (change 'Echo: ' to 'Modified: ').
    4. Verify the client receives the modified payload.
    """
    server_port = get_free_port()
    stop_event = threading.Event()

    # Start Echo Server
    server_thread = threading.Thread(target=udp_echo_server, args=(server_port, stop_event), daemon=True)
    server_thread.start()

    # PyDivert Interception
    filter_str = f"udp.SrcPort == {server_port} and loopback"
    divert_stop_event = threading.Event()
    captured_count = [0]

    if use_async:
        import asyncio

        def run_async_diverter():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(_run_diverter_async(filter_str, divert_stop_event, captured_count))
        divert_thread = threading.Thread(target=run_async_diverter, daemon=True)
    else:
        divert_thread = threading.Thread(
            target=_run_diverter,
            args=(filter_str, divert_stop_event, captured_count),
            daemon=True
        )

    divert_thread.start()
    time.sleep(2.0) # Wait for diverter to initialize

    # Retry mechanism for flakiness in CI
    max_retries = 3
    try:
        for attempt in range(max_retries):
            try:
                print(f"Test attempt {attempt + 1}/{max_retries}")
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(5.0)
                    message = b"Hello PyDivert"
                    print(f"Client sending packet to port {server_port}")
                    client.sendto(message, ("127.0.0.1", server_port))

                    try:
                        resp, _ = client.recvfrom(1024)
                        print(f"Client received response: {resp}")
                        assert resp == b"Modified: Hello PyDivert"
                        assert captured_count[0] > 0
                        return # Success!
                    except TimeoutError as e:
                        if attempt < max_retries - 1:
                            print(f"Attempt {attempt + 1} timed out, retrying...")
                            time.sleep(1.0)
                            continue
                        import os
                        if os.environ.get("GITHUB_ACTIONS"):
                            pytest.fail(
                                f"Integration timeout on {sys.platform} in CI after {max_retries} attempts: {e}. "
                                "Check permissions/routing."
                            )
                        pytest.skip(f"Timeout on {sys.platform}. Are you running as root/admin?")
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"Attempt {attempt + 1} failed with {e}, retrying...")
                    time.sleep(1.0)
                    continue
                raise
    finally:
        divert_stop_event.set()
        stop_event.set()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"STOP", ("127.0.0.1", server_port))
        divert_thread.join(timeout=2.0)
        server_thread.join(timeout=2.0)


if __name__ == "__main__":
    # For manual testing
    import unittest
    unittest.main()
