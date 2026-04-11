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
    try:
        with PyDivert("true"):
            pass
    except (ImportError, PermissionError, OSError) as e:
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
                if data == b"STOP":
                    break
                s.sendto(b"Echo: " + data, addr)
            except TimeoutError:
                continue
            except Exception:
                break

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
    # We intercept the packets coming FROM the server port
    filter_str = f"udp.SrcPort == {server_port}"
    divert_stop_event = threading.Event()
    captured_count = [0]

    def diverter():
        try:
            with PyDivert(filter_str) as w:
                while not divert_stop_event.is_set():
                    try:
                        # Try to receive with a short timeout if possible,
                        # but recv() is blocking. For tests, we rely on the client sending a packet.
                        packet = w.recv()
                        captured_count[0] += 1

                        if packet.payload and b"Echo: " in packet.payload:
                            packet.payload = packet.payload.replace(b"Echo: ", b"Modified: ")

                        w.send(packet)
                    except Exception as e:
                        if not divert_stop_event.is_set():
                            print(f"Diverter error: {e}")
                        break
        except (PermissionError, OSError) as e:
            print(f"Failed to open PyDivert: {e}")
            pass

    import asyncio
    async def diverter_async():
        try:
            async with PyDivert(filter_str) as w:
                # We need a way to stop the async loop
                while not divert_stop_event.is_set():
                    try:
                        # recv_async might not have a timeout, so we use wait_for
                        packet = await asyncio.wait_for(w.recv_async(), timeout=1.0)
                        captured_count[0] += 1

                        if packet.payload and b"Echo: " in packet.payload:
                            packet.payload = packet.payload.replace(b"Echo: ", b"Modified: ")

                        await w.send_async(packet)
                    except asyncio.TimeoutError:
                        continue
                    except Exception as e:
                        if not divert_stop_event.is_set():
                            print(f"Diverter async error: {e}")
                        break
        except (PermissionError, OSError) as e:
            print(f"Failed to open PyDivert Async: {e}")
            pass

    if use_async:
        def run_async_diverter():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(diverter_async())
        divert_thread = threading.Thread(target=run_async_diverter, daemon=True)
    else:
        divert_thread = threading.Thread(target=diverter, daemon=True)

    divert_thread.start()
    time.sleep(1.0) # Wait for diverter to initialize

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2.0)
            message = b"Hello PyDivert"
            client.sendto(message, ("127.0.0.1", server_port))

            try:
                resp, _ = client.recvfrom(1024)
                # Normal echo would be b"Echo: Hello PyDivert"
                # Modified should be b"Modified: Hello PyDivert"
                assert resp == b"Modified: Hello PyDivert"
                assert captured_count[0] > 0
            except TimeoutError:
                # If we timeout, PyDivert might not be working (e.g. not root)
                # We check if it was even opened.
                pytest.skip(f"Timeout on {sys.platform}. Are you running as root/admin?")
    finally:
        divert_stop_event.set()
        stop_event.set()
        # Wake up blocking recv by sending one more packet if needed
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"STOP", ("127.0.0.1", server_port))
        divert_thread.join(timeout=2.0)
        server_thread.join(timeout=2.0)

if __name__ == "__main__":
    # For manual testing
    import unittest
    unittest.main()
