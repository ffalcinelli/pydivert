import os
import socket
import sys
import threading

import pytest

import pydivert
from pydivert.consts import Flag, Layer

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
    ready_event = threading.Event()

    def divert_and_drop():
        try:
            with pydivert.Divert(filter_str) as w:
                ready_event.set()
                while not stop_event.is_set():
                    try:
                        w.recv(timeout=0.1)
                    except TimeoutError:
                        continue
        except (PermissionError, OSError):
            pass

    t = threading.Thread(target=divert_and_drop, daemon=True)
    t.start()
    assert ready_event.wait(timeout=10.0), "Diverter failed to start"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            with pytest.raises((socket.timeout, ConnectionRefusedError, OSError)):
                s.connect(("127.0.0.1", port))
    finally:
        stop_event.set()
        t.join(timeout=5.0)


def test_modify_port(echo_server):
    real_port = echo_server
    fake_port = 12347  # Use different port to avoid conflicts
    stop_event = threading.Event()
    ready_event = threading.Event()
    filter_str = f"tcp.DstPort == {fake_port} or tcp.SrcPort == {real_port}"

    def redirect_logic():
        try:
            with pydivert.Divert(filter_str) as w:
                ready_event.set()
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
    assert ready_event.wait(timeout=10.0), "Diverter failed to start"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect(("127.0.0.1", fake_port))
            s.sendall(b"hello")
            assert s.recv(1024) == b"hello"
    finally:
        stop_event.set()
        t.join(timeout=5.0)


def test_ebpf_interception_linux():
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux-specific test")

    port = 12348
    payload = b"EBPF_TEST_PAYLOAD"
    captured = threading.Event()
    ready_event = threading.Event()

    def diverter():
        try:
            with pydivert.Divert(f"udp.DstPort == {port}") as w:
                ready_event.set()
                packet = w.recv(timeout=3.0)
                if payload in packet.payload:
                    captured.set()
                    w.send(packet)
        except Exception:
            pass

    t = threading.Thread(target=diverter, daemon=True)
    t.start()
    assert ready_event.wait(timeout=10.0), "Diverter failed to start"

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


# --- Linux parity with WinDivert ---


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-specific test")
def test_tcp_port_matches_both_directions():
    """Both directions of a connection match (the old eBPF transpiler only matched destination ports)."""
    port = 12362
    seen = {"to": 0, "from": 0}
    stop = threading.Event()
    ready = threading.Event()

    def diverter():
        with pydivert.Divert(f"tcp.SrcPort == {port} or tcp.DstPort == {port}") as w:
            ready.set()
            while not stop.is_set():
                try:
                    p = w.recv(timeout=0.2)
                except TimeoutError:
                    continue
                seen["to" if p.dst_port == port else "from"] += 1
                w.send(p)

    t = threading.Thread(target=diverter, daemon=True)
    t.start()
    assert ready.wait(timeout=10.0)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
            conn, _ = srv.accept()
            with conn:
                c.sendall(b"ping")
                assert conn.recv(4) == b"ping"
                conn.sendall(b"pong")
                assert c.recv(4) == b"pong"
    stop.set()
    t.join(timeout=5.0)
    assert seen["to"] > 0 and seen["from"] > 0, seen


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-specific test")
def test_inexact_filter_and_matches():
    """Filters beyond the kernel rules are evaluated exactly; non-matching packets are not lost."""
    port = 12363
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
        srv.bind(("127.0.0.1", port))
        srv.settimeout(2.0)
        with pydivert.Divert(f"udp.DstPort == {port} and udp.PayloadLength > 10") as w:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
                c.sendto(b"short", ("127.0.0.1", port))
                with pytest.raises(TimeoutError):
                    w.recv(timeout=0.5)
                assert srv.recv(64) == b"short"
                c.sendto(b"long enough payload", ("127.0.0.1", port))
                p = w.recv(timeout=2.0)
                assert p.matches(f"udp.DstPort == {port} and outbound and loopback")
                assert not p.matches("tcp")
                w.send(p)
                assert srv.recv(64) == b"long enough payload"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-specific test")
def test_params_and_stats_linux():
    from pydivert.consts import Param

    with pydivert.Divert("false") as w:
        w.set_param(Param.QUEUE_LEN, 64)
        assert w.get_param(Param.QUEUE_LEN) == 64
        stats = w.stats()
        assert stats["queue_len"] == 64
        assert "diverted" in stats


# --- Event layers (FLOW, SOCKET, REFLECT) ---

EVENT_FLAGS = Flag.SNIFF | Flag.RECV_ONLY


def _recv_within(w, timeout):
    try:
        return w.recv(timeout=timeout)
    except TimeoutError:
        return None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-specific test")
def test_socket_layer_connect_event():
    port = 12390
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        with pydivert.Divert(f"event == CONNECT and remotePort == {port}", Layer.SOCKET, flags=EVENT_FLAGS) as w:
            with socket.create_connection(("127.0.0.1", port), timeout=5):
                pass
            p = _recv_within(w, 3.0)
            assert p is not None
            assert p.layer == Layer.SOCKET
            assert p.event == 4  # WINDIVERT_EVENT_SOCKET_CONNECT
            assert p.socket.RemotePort == port
            assert p.socket.Protocol == 6
            assert p.socket.ProcessId == os.getpid()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-specific test")
def test_socket_layer_blocks_connect():
    port = 12391
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", port))
        srv.listen(4)
        with pydivert.Divert(f"event == CONNECT and remotePort == {port}", Layer.SOCKET, flags=Flag.RECV_ONLY):
            with pytest.raises(PermissionError):
                socket.create_connection(("127.0.0.1", port), timeout=5)
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass
    with pytest.raises(NotImplementedError):
        # LISTEN/ACCEPT cannot be refused on Linux.
        pydivert.Divert("localPort == 1", Layer.SOCKET, flags=Flag.RECV_ONLY).open()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-specific test")
def test_flow_layer():
    port = 12392
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        with pydivert.Divert(f"remotePort == {port}", Layer.FLOW, flags=EVENT_FLAGS) as w:
            c = socket.create_connection(("127.0.0.1", port), timeout=5)
            a, _ = srv.accept()
            c.close()
            a.close()
            events = set()
            for _ in range(4):
                p = _recv_within(w, 2.0)
                if p is None:
                    break
                assert p.layer == Layer.FLOW
                events.add(p.event)
            assert events >= {1, 2}  # ESTABLISHED, DELETED


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-specific test")
def test_reflect_layer():
    with pydivert.Divert("event == OPEN and priority == 1234", Layer.REFLECT, flags=EVENT_FLAGS) as r:
        with pydivert.Divert("false", priority=1234):
            p = _recv_within(r, 3.0)
            assert p is not None
            assert p.layer == Layer.REFLECT
            assert p.reflect.Priority == 1234
            assert p.reflect.ProcessId == os.getpid()
            assert bytes(p.raw).startswith(b"@WinDiv_")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-specific test")
def test_event_layer_flags_validated():
    with pytest.raises(OSError):
        pydivert.Divert("true", Layer.FLOW, flags=Flag.RECV_ONLY).open()
