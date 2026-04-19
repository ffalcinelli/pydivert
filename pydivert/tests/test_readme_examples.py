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

"""
Integration tests for each example provided in the README.md.
"""

import asyncio
import socket
import sys
import threading
import time

import pytest

import pydivert
from pydivert import Flag, Layer
from pydivert.packet import Packet
from pydivert.packet.tcp import TCPHeader


def setup_module(module):
    """Skip all tests in this module if PyDivert cannot be initialized locally.
    Integration tests should ideally only run on the platform they target.
    """
    # For README examples, they are cross-platform, but need permissions.
    try:
        with pydivert.PyDivert("true"):
            pass
    except (ImportError, PermissionError, OSError, RuntimeError) as e:
        pytest.skip(f"PyDivert not available: {e}. Check permissions/dependencies.")


def get_free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_example_basic_capture():
    # Example: Basic Capture and Re-injection
    port = get_free_port()

    def server():
        with socket.socket() as s:
            s.settimeout(5.0)
            s.bind(("127.0.0.1", port))
            s.listen(1)
            try:
                conn, addr = s.accept()
                conn.settimeout(5.0)
                data = conn.recv(1024)
                conn.sendall(data)
                conn.close()
            except Exception:
                pass

    t1 = threading.Thread(target=server, daemon=True)
    t1.start()

    stop_event = threading.Event()

    def diverter():
        with pydivert.PyDivert(f"tcp.DstPort == {port}") as w:
            for packet in w:
                if stop_event.is_set():
                    break
                w.send(packet)

    t2 = threading.Thread(target=diverter, daemon=True)
    t2.start()
    time.sleep(1.0)

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            client.sendall(b"test")
            assert client.recv(1024) == b"test"
    finally:
        stop_event.set()
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except Exception:
            pass
        t1.join(timeout=1.0)
        t2.join(timeout=1.0)


def test_example_packet_modification_redirection():
    # Example: Packet Modification (Port Redirection)
    real_port = get_free_port()
    fake_port = get_free_port()
    while fake_port == real_port:
        fake_port = get_free_port()

    def server():
        with socket.socket() as s:
            s.settimeout(5.0)
            s.bind(("127.0.0.1", real_port))
            s.listen(1)
            try:
                conn, addr = s.accept()
                conn.settimeout(5.0)
                conn.recv(1024)
                conn.sendall(b"redirected")
                conn.close()
            except Exception:
                pass

    t1 = threading.Thread(target=server, daemon=True)
    t1.start()

    stop_event = threading.Event()

    def diverter():
        # Capturing both directions
        with pydivert.PyDivert(f"tcp.DstPort == {fake_port} or tcp.SrcPort == {real_port}") as w:
            for packet in w:
                if stop_event.is_set():
                    break
                if packet.dst_port == fake_port:
                    packet.dst_port = real_port
                elif packet.src_port == real_port:
                    packet.src_port = fake_port
                w.send(packet)

    t2 = threading.Thread(target=diverter, daemon=True)
    t2.start()
    time.sleep(2.0)

    try:
        with socket.create_connection(("127.0.0.1", fake_port), timeout=10) as client:
            client.sendall(b"hi")
            assert client.recv(1024) == b"redirected"
    finally:
        stop_event.set()
        try:
            socket.create_connection(("127.0.0.1", fake_port), timeout=0.1)
        except Exception:
            pass
        t1.join(timeout=1.0)
        t2.join(timeout=1.0)


def test_example_firewall_drop():
    # Example: Simple Firewall (Dropping Packets)
    port = get_free_port()

    def server():
        with socket.socket() as s:
            s.settimeout(5.0)
            s.bind(("127.0.0.1", port))
            s.listen(1)
            try:
                s.accept()
            except Exception:
                pass

    t1 = threading.Thread(target=server, daemon=True)
    t1.start()

    stop_event = threading.Event()

    def diverter():
        with pydivert.PyDivert(f"tcp.DstPort == {port}") as w:
            for _packet in w:
                if stop_event.is_set():
                    break
                # Drop it by NOT sending
                pass

    t2 = threading.Thread(target=diverter, daemon=True)
    t2.start()
    time.sleep(1.0)

    try:
        with socket.socket() as client:
            client.settimeout(1)
            # Connecting to port on 127.0.0.1 with Diverter dropping packets should timeout.
            with pytest.raises(socket.timeout):
                client.connect(("127.0.0.1", port))
    finally:
        stop_event.set()
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except Exception:
            pass
        t1.join(timeout=1.0)
        t2.join(timeout=1.0)


def test_example_payload_modification():
    # Example: Payload Inspection and Modification
    port = get_free_port()

    def server():
        with socket.socket() as s:
            s.settimeout(5.0)
            s.bind(("127.0.0.1", port))
            s.listen(1)
            try:
                conn, addr = s.accept()
                conn.settimeout(5.0)
                conn.sendall(b"Your secret-token is 123")
                conn.close()
            except Exception:
                pass

    t1 = threading.Thread(target=server, daemon=True)
    t1.start()

    stop_event = threading.Event()

    def diverter():
        with pydivert.PyDivert(f"tcp.SrcPort == {port} and tcp.PayloadLength > 0") as w:
            for packet in w:
                if stop_event.is_set():
                    break
                if packet.payload and b"secret-token" in packet.payload:
                    packet.payload = packet.payload.replace(b"secret-token", b"REDACTED")
                w.send(packet)

    t2 = threading.Thread(target=diverter, daemon=True)
    t2.start()
    time.sleep(1.0)

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            data = client.recv(1024)
            assert b"REDACTED" in data
            assert b"secret-token" not in data
    finally:
        stop_event.set()
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except Exception:
            pass
        t1.join(timeout=1.0)
        t2.join(timeout=1.0)


def test_example_traffic_logging():
    # Example: Traffic Logging
    port = get_free_port()

    def server():
        with socket.socket() as s:
            s.settimeout(5.0)
            s.bind(("127.0.0.1", port))
            s.listen(1)
            try:
                conn, addr = s.accept()
                conn.settimeout(5.0)
                conn.recv(1024)
                conn.close()
            except Exception:
                pass

    t1 = threading.Thread(target=server, daemon=True)
    t1.start()

    captured_info = []
    stop_event = threading.Event()

    def diverter():
        with pydivert.PyDivert(f"tcp.DstPort == {port}") as w:
            for packet in w:
                if stop_event.is_set():
                    break
                direction = "OUT" if packet.is_outbound else "IN "
                captured_info.append(f"[{direction}] {packet.src_addr}:{packet.src_port}")
                w.send(packet)

    t2 = threading.Thread(target=diverter, daemon=True)
    t2.start()
    time.sleep(1.0)

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            client.sendall(b"data")
    finally:
        stop_event.set()
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except Exception:
            pass
        t1.join(timeout=1.0)
        t2.join(timeout=1.0)

    assert captured_info


def flow_layer_diverter(port, stop_event, events):
    # Layer.FLOW doesn't capture packets but events.
    # Some filters are not supported on Layer.FLOW, use "true" and filter in Python.
    # Also using RECV_ONLY as FLOW re-injection is complex.
    try:
        with pydivert.PyDivert("true", layer=Layer.FLOW, flags=Flag.RECV_ONLY) as w:
            for event in w:
                if stop_event.is_set():
                    break

                # Check if it's our connection
                if event.flow and (event.flow.LocalPort == port or event.flow.RemotePort == port):
                    events.append(event)
    except OSError as e:
        if getattr(e, "winerror", None) == 87:
            events.append("SKIP_WINERROR_87")
        else:
            events.append(e)
    except Exception as e:
        events.append(e)


def flow_layer_server(port):
    with socket.socket() as s:
        s.settimeout(5.0)
        s.bind(("127.0.0.1", port))
        s.listen(1)
        try:
            conn, _ = s.accept()
            conn.close()
        except Exception:
            pass


@pytest.mark.skipif(sys.platform != 'win32', reason="Windows only")
def test_example_flow_layer():
    # Example: WinDivert Layers (FLOW)
    port = get_free_port()

    events = []
    stop_event = threading.Event()

    t1 = threading.Thread(target=flow_layer_diverter, args=(port, stop_event, events), daemon=True)
    t1.start()
    time.sleep(1.0)

    if events and events[0] == "SKIP_WINERROR_87":
        pytest.skip("Layer.FLOW is not supported on this environment (WinError 87)")

    t2 = threading.Thread(target=flow_layer_server, args=(port,), daemon=True)
    t2.start()

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
    finally:
        stop_event.set()
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except Exception:
            pass
        t1.join(timeout=1.0)
        t2.join(timeout=1.0)

    if events and isinstance(events[0], Exception):
        pytest.fail(f"Diverter thread failed: {events[0]}")

    assert events
    assert any(hasattr(e, "layer") and e.layer == Layer.FLOW for e in events if not isinstance(e, Exception))


@pytest.mark.skipif(sys.platform != 'win32', reason="Windows only")
def test_example_sniff_mode():
    # Example: Flags (SNIFF)
    port = get_free_port()

    def server():
        with socket.socket() as s:
            s.settimeout(5.0)
            s.bind(("127.0.0.1", port))
            s.listen(1)
            try:
                conn, addr = s.accept()
                conn.settimeout(5.0)
                data = conn.recv(1024)
                conn.sendall(data)
                conn.close()
            except Exception:
                pass

    t1 = threading.Thread(target=server, daemon=True)
    t1.start()

    sniffed_packets = []
    stop_event = threading.Event()

    def diverter():
        with pydivert.PyDivert(f"tcp.DstPort == {port}", flags=Flag.SNIFF) as w:
            for packet in w:
                if stop_event.is_set():
                    break
                sniffed_packets.append(packet)

    t2 = threading.Thread(target=diverter, daemon=True)
    t2.start()
    time.sleep(1.0)

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            client.sendall(b"sniff-me")
            assert client.recv(1024) == b"sniff-me"
    finally:
        stop_event.set()
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except Exception:
            pass
        t1.join(timeout=1.0)
        t2.join(timeout=1.0)

    assert sniffed_packets


@pytest.mark.asyncio
async def test_example_asyncio():
    # Example: First-Class asyncio Support
    port = get_free_port()

    def server():
        with socket.socket() as s:
            s.settimeout(5.0)
            s.bind(("127.0.0.1", port))
            s.listen(1)
            try:
                conn, _ = s.accept()
                conn.settimeout(5.0)
                conn.recv(1024)
                conn.close()
            except Exception:
                pass

    t1 = threading.Thread(target=server, daemon=True)
    t1.start()

    captured = []
    stop_event = asyncio.Event()

    async def diverter():
        try:
            async with pydivert.PyDivert(f"tcp.DstPort == {port}") as w:
                async for packet in w:
                    captured.append(packet)
                    await w.send_async(packet)
                    if stop_event.is_set():
                        break
        except (PermissionError, OSError):
            pass

    diverter_task = asyncio.create_task(diverter())
    await asyncio.sleep(1.0)

    try:
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"async-test")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    except (PermissionError, OSError):
        pytest.skip("Test requires administrator privileges.")
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
        t1.join(timeout=1.0)

    assert captured


def test_example_pattern_matching():
    # Example: Structural Pattern Matching

    # Mock a packet
    raw = bytearray(40)
    raw[0] = 0x45
    raw[9] = 6
    raw[22:24] = b"\x00\x50" # port 80
    packet = Packet(raw)

    matched_http = False
    match packet:
        case Packet(tcp=TCPHeader(dst_port=80)):
            matched_http = True

    assert matched_http
