import socket
import sys
import threading
import time

import pytest

import pydivert
from pydivert.consts import Flag

# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils

# --- Fixtures & Servers ---


@pytest.fixture
def echo_server():
    """A simple TCP echo server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(5)
    stop_event = threading.Event()

    def run():
        sock.settimeout(1.0)
        while not stop_event.is_set():
            try:
                conn, addr = sock.accept()
                with conn:
                    data = conn.recv(1024)
                    if data:
                        conn.sendall(data)
            except TimeoutError:
                continue
            except Exception:
                break
        sock.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    yield port
    stop_event.set()
    thread.join(timeout=2.0)


# --- Integration Scenarios ---


def test_drop_tcp(echo_server):
    port = echo_server
    filter_str = f"tcp.DstPort == {port}"
    stop_event = threading.Event()

    def divert_and_drop():
        try:
            with pydivert.Divert(filter_str) as w:
                while not stop_event.is_set():
                    try:
                        w.recv(timeout=0.1)
                    except TimeoutError:
                        continue
        except (PermissionError, OSError):
            pass

    t = threading.Thread(target=divert_and_drop, daemon=True)
    t.start()
    time.sleep(0.5)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            with pytest.raises((socket.timeout, ConnectionRefusedError, OSError)):
                s.connect(("127.0.0.1", port))
    finally:
        stop_event.set()
        t.join(timeout=1.0)


def test_modify_port(echo_server):
    real_port = echo_server
    fake_port = 12347  # Use different port to avoid conflicts
    stop_event = threading.Event()
    filter_str = f"tcp.DstPort == {fake_port} or tcp.SrcPort == {real_port}"

    def redirect_logic():
        try:
            with pydivert.Divert(filter_str) as w:
                while not stop_event.is_set():
                    try:
                        packet = w.recv(timeout=0.1)
                        if packet.tcp:
                            if packet.tcp.dst_port == fake_port:
                                packet.tcp.dst_port = real_port
                            elif packet.tcp.src_port == real_port:
                                packet.tcp.src_port = fake_port
                        w.send(packet)
                    except TimeoutError:
                        continue
        except (PermissionError, OSError):
            pass

    t = threading.Thread(target=redirect_logic, daemon=True)
    t.start()
    time.sleep(0.5)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect(("127.0.0.1", fake_port))
            s.sendall(b"hello")
            assert s.recv(1024) == b"hello"
    finally:
        stop_event.set()
        t.join(timeout=1.0)


def test_ebpf_interception_linux():
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux-specific test")

    port = 12348
    payload = b"EBPF_TEST_PAYLOAD"
    captured = threading.Event()

    def diverter():
        try:
            with pydivert.Divert(f"udp.DstPort == {port}") as w:
                packet = w.recv(timeout=3.0)
                if payload in packet.payload:
                    captured.set()
                    w.send(packet)
        except Exception:
            pass

    t = threading.Thread(target=diverter, daemon=True)
    t.start()
    time.sleep(0.5)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(payload, ("127.0.0.1", port))

    t.join(timeout=4.0)
    assert captured.is_set()


# --- Advanced Flags ---


def test_flags_behavior():
    try:
        with pydivert.Divert("false", flags=Flag.RECV_ONLY) as w:
            with pytest.raises(OSError):
                w.send(pydivert.Packet(b"E" + b"\x00" * 19))
    except (PermissionError, OSError):
        pytest.skip("Insufficient privileges")


import pytest
