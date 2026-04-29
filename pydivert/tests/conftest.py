# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import itertools
import socket
import threading
from queue import Queue

import pytest

import pydivert
from pydivert.tests.util import check_availability


@pytest.fixture(autouse=True)
def check_pydivert_availability(request):
    """Automatically skips integration tests if PyDivert is unavailable."""
    # Only run this check for integration tests (those not using mocks)
    if "mock" in request.node.name or "mock" in request.node.nodeid:
        return

    integration_keywords = (
        "integration",
        "ping_pong",
        "asyncio_modern",
        "windivert",
        "driver",
        "scenario",
        "example",
        "multiprocessing",
        "header_integration",
    )
    is_integration = any(kw in request.module.__name__ for kw in integration_keywords)

    if is_integration or request.node.get_closest_marker("integration"):
        check_availability()


@pytest.fixture
def windivert_handle():
    """Fixture providing a WinDivert handle (cross-platform facade)."""
    with pydivert.PyDivert("false") as w:
        yield w


@pytest.fixture
def packet_factory():
    """Returns a factory function to create packets for testing."""

    def create_packet(raw_hex, interface=(1, 1), direction=pydivert.Direction.OUTBOUND, **kwargs):
        from pydivert import util

        raw = util.fromhex(raw_hex) if isinstance(raw_hex, str) else raw_hex
        return pydivert.Packet(raw, interface=interface, direction=direction, **kwargs)

    return create_packet


def _setup_tcp(server, client, reply):
    def server_echo():
        server.settimeout(5.0)
        server.listen(1)
        try:
            conn, addr = server.accept()
            conn.settimeout(5.0)
            conn.sendall(conn.recv(4096).upper())
            conn.close()
        except (TimeoutError, OSError):
            pass

    def send(addr, data):
        client.settimeout(5.0)
        client.connect(addr)
        client.sendall(data)
        try:
            reply.put(client.recv(4096))
        except (TimeoutError, OSError):
            reply.put(None)

    return server_echo, send


def _setup_udp(server, client, reply):
    def server_echo():
        server.settimeout(5.0)
        try:
            data, addr = server.recvfrom(4096)
            server.sendto(data.upper(), addr)
        except (TimeoutError, OSError):
            pass

    def send(addr, data):
        client.settimeout(5.0)
        client.sendto(data, addr)
        try:
            data, recv_addr = client.recvfrom(4096)
            assert addr[:2] == recv_addr[:2]  # only accept responses from the same host
            reply.put(data)
        except (TimeoutError, OSError, AssertionError):
            reply.put(None)

    return server_echo, send


@pytest.fixture(
    params=list(
        itertools.product(
            ("ipv4", "ipv6"),
            ("tcp", "udp"),
        )
    ),
    ids=lambda x: ",".join(x),
)
def scenario(request):
    ip_version, proto = request.param

    if ip_version == "ipv4":
        atype = socket.AF_INET
        host = "127.0.0.1"
    else:
        atype = socket.AF_INET6
        host = "::1"

    stype = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM

    with socket.socket(atype, stype) as server, socket.socket(atype, stype) as client:
        server.bind((host, 0))
        client.bind((host, 0))

        reply = Queue()

        if proto == "tcp":
            server_echo, send = _setup_tcp(server, client, reply)
        else:
            server_echo, send = _setup_udp(server, client, reply)

        server_thread = threading.Thread(target=server_echo, daemon=True)
        server_thread.start()

        filt = f"{proto}.SrcPort == {client.getsockname()[1]} or {proto}.SrcPort == {server.getsockname()[1]}"

        def send_thread(*args, **kwargs):
            threading.Thread(target=send, args=args, kwargs=kwargs, daemon=True).start()
            return reply

        with pydivert.PyDivert(filt) as w:
            yield client.getsockname(), server.getsockname(), w, send_thread
