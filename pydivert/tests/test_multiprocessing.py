# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of either:
#
# 1) The GNU Lesser General Public License as published by the Free
#    Software Foundation, either version 3 of the License, or (at your
#    option) any later version.
#
# 2) The GNU General Public License as published by the Free Software
#    Foundation, either version 2 of the License, or (at your option)
#    any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License and the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# and the GNU General Public License along with this program.  If not,
# see <https://www.gnu.org/licenses/>.

import multiprocessing
import socket
import sys
import time

import pytest

import pydivert


def run_recv_no_open(queue):
    try:
        w = pydivert.WinDivert("false")
        w.recv()
    except RuntimeError as e:
        queue.put(str(e))
    except Exception as e:
        queue.put(f"Unexpected exception: {type(e).__name__}: {e}")
    else:
        queue.put("No exception raised")


def run_recv_with_context_manager(queue):
    try:
        with pydivert.WinDivert("false"):
            queue.put("Success")
            # We don't actually recv() here because it would block indefinitely on "false" filter
    except Exception as e:
        queue.put(f"Caught: {type(e).__name__}: {e}")


def server_worker(stop_event, barrier, results_queue):
    """
    Subprocess that runs a simple UDP echo server and captures traffic via WinDivert.
    """
    # Setup UDP server
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

        # Tell the main process our port
        results_queue.put(port)

        # Wait for main process to be ready
        barrier.wait()

        try:
            with pydivert.WinDivert(f"udp and udp.DstPort == {port}") as w:
                while not stop_event.is_set():
                    try:
                        # We expect 1 packet
                        packet = w.recv()
                        results_queue.put(f"Captured: {packet.dst_port}")
                        w.send(packet)

                        # Also handle the socket side so the client gets a reply
                        sock.settimeout(1.0)
                        data, addr = sock.recvfrom(4096)
                        sock.sendto(data.upper(), addr)
                        break  # Done for this test
                    except TimeoutError:
                        continue
                    except Exception as e:
                        results_queue.put(f"WinDivert Error: {e}")
                        break
        except Exception as e:
            results_queue.put(f"Worker Error: {e}")


@pytest.mark.skipif(sys.platform != "win32", reason="WinDivert is Windows-only")
def test_multiprocessing_no_open():
    queue = multiprocessing.Queue()
    p = multiprocessing.Process(target=run_recv_no_open, args=(queue,))
    p.start()
    p.join()

    result = queue.get()
    assert result == "WinDivert handle is not open"


@pytest.mark.skipif(sys.platform != "win32", reason="WinDivert is Windows-only")
def test_multiprocessing_with_context_manager():
    queue = multiprocessing.Queue()
    p = multiprocessing.Process(target=run_recv_with_context_manager, args=(queue,))
    p.start()
    p.join()

    result = queue.get()
    # On systems without the driver, this might be an OSError.
    # On systems with the driver, it should be "Success".
    # In neither case should it be the "WinDivert handle is not open" RuntimeError.
    assert result != "WinDivert handle is not open"


@pytest.mark.skipif(sys.platform != "win32", reason="WinDivert is Windows-only")
def test_multiprocessing_integration_simple():
    stop_event = multiprocessing.Event()
    results_queue = multiprocessing.Queue()
    barrier = multiprocessing.Barrier(2)

    p = multiprocessing.Process(target=server_worker, args=(stop_event, barrier, results_queue))
    p.start()

    # Get the port from the subprocess
    try:
        port = results_queue.get(timeout=20)
    except Exception:
        p.terminate()
        raise

    # Sync up
    barrier.wait()
    time.sleep(2)  # Extra buffer for WinDivertOpen

    try:
        # Send UDP packet
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(10)
            client.sendto(b"hello", ("127.0.0.1", port))

            data, _ = client.recvfrom(4096)
            assert data == b"HELLO"

        # Check WinDivert capture in subprocess
        capture_msg = results_queue.get(timeout=10)
        assert f"Captured: {port}" == capture_msg
    finally:
        stop_event.set()
        p.terminate()
        p.join()
