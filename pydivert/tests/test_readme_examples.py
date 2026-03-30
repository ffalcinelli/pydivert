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
# see <http://www.gnu.org/licenses/>.

"""
Integration tests for each example provided in the README.md.
"""

import socket
import threading
import time

import pytest

import pydivert
from pydivert import Flag, Layer


def get_free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_example_basic_capture():
    # Example: Basic Capture and Re-injection
    port = get_free_port()

    def server():
        s = socket.socket()
        s.bind(("127.0.0.1", port))
        s.listen(1)
        try:
            conn, addr = s.accept()
            data = conn.recv(1024)
            conn.sendall(data)
            conn.close()
        except Exception:
            pass
        s.close()

    threading.Thread(target=server, daemon=True).start()

    stop_event = threading.Event()

    def diverter():
        with pydivert.WinDivert(f"tcp.DstPort == {port}") as w:
            for packet in w:
                if stop_event.is_set():
                    break
                w.send(packet)

    threading.Thread(target=diverter, daemon=True).start()
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


def test_example_packet_modification_redirection():
    # Example: Packet Modification (Port Redirection)
    real_port = get_free_port()
    fake_port = get_free_port()
    while fake_port == real_port:
        fake_port = get_free_port()

    def server():
        s = socket.socket()
        s.bind(("127.0.0.1", real_port))
        s.listen(1)
        try:
            conn, addr = s.accept()
            conn.recv(1024)
            conn.sendall(b"redirected")
            conn.close()
        except Exception:
            pass
        s.close()

    threading.Thread(target=server, daemon=True).start()

    stop_event = threading.Event()

    def diverter():
        # Capturing both directions
        with pydivert.WinDivert(f"tcp.DstPort == {fake_port} or tcp.SrcPort == {real_port}") as w:
            for packet in w:
                if stop_event.is_set():
                    break
                if packet.dst_port == fake_port:
                    packet.dst_port = real_port
                elif packet.src_port == real_port:
                    packet.src_port = fake_port
                w.send(packet)

    threading.Thread(target=diverter, daemon=True).start()
    time.sleep(1.0)

    try:
        with socket.create_connection(("127.0.0.1", fake_port), timeout=2) as client:
            client.sendall(b"hi")
            assert client.recv(1024) == b"redirected"
    finally:
        stop_event.set()
        try:
            socket.create_connection(("127.0.0.1", fake_port), timeout=0.1)
        except Exception:
            pass


def test_example_firewall_drop():
    # Example: Simple Firewall (Dropping Packets)
    port = get_free_port()

    def server():
        s = socket.socket()
        s.bind(("127.0.0.1", port))
        s.listen(1)
        try:
            s.accept()
        except Exception:
            pass
        s.close()

    threading.Thread(target=server, daemon=True).start()

    stop_event = threading.Event()

    def diverter():
        with pydivert.WinDivert(f"tcp.DstPort == {port}") as w:
            for _packet in w:
                if stop_event.is_set():
                    break
                # Drop it by NOT sending
                pass

    threading.Thread(target=diverter, daemon=True).start()
    time.sleep(1.0)

    try:
        with socket.socket() as client:
            client.settimeout(1)
            # Connecting to port on 127.0.0.1 with Diverter dropping packets should timeout.
            with pytest.raises(socket.timeout):
                client.connect(("127.0.0.1", port))
    finally:
        stop_event.set()


def test_example_payload_modification():
    # Example: Payload Inspection and Modification
    port = get_free_port()

    def server():
        s = socket.socket()
        s.bind(("127.0.0.1", port))
        s.listen(1)
        try:
            conn, addr = s.accept()
            conn.sendall(b"Your secret-token is 123")
            conn.close()
        except Exception:
            pass
        s.close()

    threading.Thread(target=server, daemon=True).start()

    stop_event = threading.Event()

    def diverter():
        with pydivert.WinDivert(f"tcp.SrcPort == {port} and tcp.PayloadLength > 0") as w:
            for packet in w:
                if stop_event.is_set():
                    break
                if b"secret-token" in packet.payload:
                    packet.payload = packet.payload.replace(b"secret-token", b"REDACTED")
                w.send(packet)

    threading.Thread(target=diverter, daemon=True).start()
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


def test_example_traffic_logging():
    # Example: Traffic Logging
    port = get_free_port()

    def server():
        s = socket.socket()
        s.bind(("127.0.0.1", port))
        s.listen(1)
        try:
            conn, addr = s.accept()
            conn.recv(1024)
            conn.close()
        except Exception:
            pass
        s.close()

    threading.Thread(target=server, daemon=True).start()

    captured_info = []
    stop_event = threading.Event()

    def diverter():
        with pydivert.WinDivert(f"tcp.DstPort == {port}") as w:
            for packet in w:
                if stop_event.is_set():
                    break
                direction = "OUT" if packet.is_outbound else "IN "
                captured_info.append(f"[{direction}] {packet.src_addr}:{packet.src_port}")
                w.send(packet)

    threading.Thread(target=diverter, daemon=True).start()
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

    assert len(captured_info) > 0


def flow_layer_diverter(port, stop_event, events):
    # Layer.FLOW doesn't capture packets but events.
    # Some filters are not supported on Layer.FLOW, use "true" and filter in Python.
    # Also using RECV_ONLY as FLOW re-injection is complex.
    try:
        with pydivert.WinDivert("true", layer=Layer.FLOW, flags=Flag.RECV_ONLY) as w:
            for event in w:
                if stop_event.is_set():
                    break

                # Check if it's our connection
                if event.flow and (event.flow.LocalPort == port or event.flow.RemotePort == port):
                    events.append(event)
    except OSError as e:
        if e.winerror == 87:
            events.append("SKIP_WINERROR_87")
        else:
            events.append(e)
    except Exception as e:
        events.append(e)


def flow_layer_server(port):
    s = socket.socket()
    s.bind(("127.0.0.1", port))
    s.listen(1)
    try:
        conn, _ = s.accept()
        conn.close()
    except Exception:
        pass
    s.close()


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
    finally:
        stop_event.set()
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except Exception:
            pass

    if len(events) > 0 and isinstance(events[0], Exception):
        pytest.fail(f"Diverter thread failed: {events[0]}")

    assert len(events) > 0
    assert any(hasattr(e, "layer") and e.layer == Layer.FLOW for e in events if not isinstance(e, Exception))


def test_example_sniff_mode():
    # Example: Flags (SNIFF)
    port = get_free_port()

    def server():
        s = socket.socket()
        s.bind(("127.0.0.1", port))
        s.listen(1)
        try:
            conn, addr = s.accept()
            data = conn.recv(1024)
            conn.sendall(data)
            conn.close()
        except Exception:
            pass
        s.close()

    threading.Thread(target=server, daemon=True).start()

    sniffed_packets = []
    stop_event = threading.Event()

    def diverter():
        with pydivert.WinDivert(f"tcp.DstPort == {port}", flags=Flag.SNIFF) as w:
            for packet in w:
                if stop_event.is_set():
                    break
                sniffed_packets.append(packet)

    threading.Thread(target=diverter, daemon=True).start()
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

    assert len(sniffed_packets) > 0
