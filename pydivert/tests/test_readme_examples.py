# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of either:
#
#   * the GNU Lesser General Public License as published by the Free
#     Software Foundation, either version 3 of the License, or (at
#     your option) any later version.
#
#   * the GNU General Public License as published by the Free
#     Software Foundation, either version 2 of the License, or (at
#     your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License and the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License and the GNU General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

import asyncio
import socket
import sys
import threading
import time

import pytest

import pydivert
from pydivert.consts import Flag, Layer


def get_free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_example_basic():
    # Example: Basic Usage
    with pydivert.Divert("icmp") as w:
        # We can't easily trigger ICMP here without scapy or similar
        # and we don't want to rely on external network.
        # Just check it opens correctly.
        assert w.is_open


def test_example_modification():
    # Example: Packet Modification
    port = get_free_port()

    def server():
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(1)
            try:
                conn, _ = s.accept()
                data = conn.recv(1024)
                conn.sendall(data.upper())
                conn.close()
            except Exception:
                pass

    threading.Thread(target=server, daemon=True).start()

    with pydivert.Divert(f"tcp.DstPort == {port}") as w:
        # Connect in a separate thread to avoid deadlock
        captured_info = []

        def client():
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                    s.sendall(b"hello")
                    captured_info.append(s.recv(1024))
            except Exception as e:
                captured_info.append(e)

        threading.Thread(target=client).start()

        # Loop until we have modified the payload or timeout
        start = time.time()
        while time.time() - start < 5.0:
            try:
                packet = w.recv(timeout=1.0)
                if packet.tcp and b"hello" in packet.tcp.payload:
                    packet.tcp.payload = packet.tcp.payload.replace(b"hello", b"HELLO")
                w.send(packet)
            except TimeoutError:
                break
            if captured_info:
                break

        time.sleep(0.5)
        assert captured_info == [b"HELLO"]


def flow_layer_diverter(port, stop_event, events):
    try:
        print(f"Flow diverter starting for port {port}")
        with pydivert.Divert(
            f"tcp.DstPort == {port} or tcp.SrcPort == {port}", layer=Layer.FLOW, flags=Flag.RECV_ONLY
        ) as w:
            while not stop_event.is_set():
                try:
                    event = w.recv(timeout=0.1)
                    if event.flow:
                        print(
                            f"Captured flow: LPort={event.flow.LocalPort}, "
                            f"RPort={event.flow.RemotePort}, Proto={event.flow.Protocol}"
                        )
                    if event.flow and (event.flow.LocalPort == port or event.flow.RemotePort == port):
                        print("Found our flow!")
                        events.append(event)
                except TimeoutError:
                    continue
    except OSError as e:
        if getattr(e, "winerror", None) == 87:
            events.append("SKIP_WINERROR_87")
        else:
            print(f"Flow diverter error: {e}")
            events.append(e)
    except Exception as e:
        print(f"Flow diverter unexpected error: {e}")
        events.append(e)
    print("Flow diverter stopped")


def flow_layer_server(port):
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(1)
        try:
            conn, _ = s.accept()
            conn.close()
        except Exception:
            pass


def test_example_flow_layer():
    # Example: WinDivert Layers (FLOW)
    port = get_free_port()

    events = []
    stop_event = threading.Event()

    threading.Thread(target=flow_layer_diverter, args=(port, stop_event, events), daemon=True).start()
    time.sleep(1.0)

    if events and events[0] == "SKIP_WINERROR_87":
        pytest.skip("Layer.FLOW is not supported on this environment (WinError 87)")

    threading.Thread(target=flow_layer_server, args=(port,), daemon=True).start()

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
    except Exception as e:
        print(f"Client connection failed: {e}")
    finally:
        stop_event.set()
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except Exception:
            pass

    # Wait up to 5 seconds for events to be captured
    start_wait = time.time()
    while len(events) == 0 and time.time() - start_wait < 5.0:
        time.sleep(0.1)

    if events and isinstance(events[0], Exception):
        pytest.fail(f"Diverter thread failed: {events[0]}")

    assert events
    assert any(hasattr(e, "layer") and e.layer == Layer.FLOW for e in events if not isinstance(e, Exception))


def test_example_sniff_mode():
    # Example: Flags (SNIFF)
    port = get_free_port()

    def server():
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(1)
            try:
                conn, addr = s.accept()
                data = conn.recv(1024)
                conn.sendall(data)
                conn.close()
            except Exception:
                pass

    threading.Thread(target=server, daemon=True).start()

    sniffed_packets = []
    stop_event = threading.Event()

    def diverter():
        print(f"Diverter starting for port {port}")
        try:
            with pydivert.Divert(f"tcp.DstPort == {port}", flags=Flag.SNIFF) as w:
                while not stop_event.is_set():
                    try:
                        packet = w.recv(timeout=0.1)
                        print(f"Diverter captured packet: {packet}")
                        sniffed_packets.append(packet)
                    except TimeoutError:
                        continue
        except Exception as e:
            print(f"Diverter error: {e}")
        print("Diverter finished")

    threading.Thread(target=diverter, daemon=True).start()
    time.sleep(1.0)

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            print("Client connected")
            client.sendall(b"sniff-me")
            data = client.recv(1024)
            print(f"Client received: {data}")
            assert data == b"sniff-me"
    finally:
        print("Setting stop_event")
        stop_event.set()
        try:
            # Trigger one more packet to unblock recv if needed
            socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except Exception:
            pass

    # Wait up to 5 seconds for packets to be captured
    start_wait = time.time()
    while len(sniffed_packets) == 0 and time.time() - start_wait < 5.0:
        time.sleep(0.1)

    print(f"Sniffed packets count: {len(sniffed_packets)}")
    assert sniffed_packets


def _async_example_server(port):
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(1)
        try:
            conn, _ = s.accept()
            conn.recv(1024)
            conn.close()
        except Exception:
            pass


async def _async_example_diverter(port, captured, stop_event):
    try:
        # Use 'loopback' in filter for Windows reliability
        filt = f"tcp.DstPort == {port}"
        if sys.platform == "win32":
            filt += " and loopback"

        async with pydivert.Divert(filt, flags=pydivert.Flag.SNIFF) as w:
            while not stop_event.is_set():
                try:
                    # Use native timeout
                    packet = await w.recv_async(timeout=0.1)
                    captured.append(packet)
                    # No need to send back in SNIFF mode
                except TimeoutError:
                    continue
    except (PermissionError, OSError) as e:
        print(f"Async diverter error: {e}")


@pytest.mark.asyncio
async def test_example_asyncio():
    # Example: First-Class asyncio Support
    port = get_free_port()

    threading.Thread(target=_async_example_server, args=(port,), daemon=True).start()

    captured = []
    stop_event = asyncio.Event()

    diverter_task = asyncio.create_task(_async_example_diverter(port, captured, stop_event))
    await asyncio.sleep(1.0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"async-test")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    except (PermissionError, OSError):
        pytest.skip("Test requires administrator privileges.")
    except Exception as e:
        print(f"Async client failed: {e}")
    finally:
        stop_event.set()
        # Trigger one more recv to stop the iterator
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
        except Exception:
            pass
        await asyncio.sleep(0.5)
        diverter_task.cancel()

    assert captured


def test_example_pattern_matching():
    # Example: Structural Pattern Matching

    # Mock a packet
    raw = bytearray(40)
    raw[0] = 0x45
    raw[9] = 6
    raw[22:24] = b"\x00\x50"  # port 80


    from pydivert.packet.tcp import TCPHeader

    p = pydivert.Packet(raw, direction=pydivert.Direction.INBOUND)

    match p:
        case pydivert.Packet(tcp=TCPHeader(dst_port=80)):
            matched = True
        case _:
            matched = False

    assert matched
