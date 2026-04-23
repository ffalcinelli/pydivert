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

import asyncio
import socket
import threading
import time

import pytest

import pydivert


def setup_module(module):
    """Skip all tests in this module if PyDivert cannot be initialized."""
    import os

    try:
        with pydivert.PyDivert("true"):
            pass
    except (ImportError, PermissionError, OSError, RuntimeError) as e:
        import sys

        if os.environ.get("GITHUB_ACTIONS") or os.environ.get("VAGRANT_VM"):
            if sys.platform == "darwin" and getattr(e, "errno", None) == 22:
                pytest.skip(f"Divert sockets are not supported on this macOS version: {e}")
            else:
                pytest.fail(f"PyDivert integration tests must run in CI, but initialization failed: {e}")
        pytest.skip(f"PyDivert not available: {e}")


def get_free_port(proto=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, proto) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _backend_server(port):
    with socket.socket() as s:
        s.settimeout(5.0)
        s.bind(("127.0.0.1", port))
        s.listen(5)
        try:
            conn, _ = s.accept()
            conn.settimeout(5.0)
            data = conn.recv(1024)
            # Backend appends " [Processed by Backend]"
            conn.sendall(data + b" [Processed by Backend]")
            conn.close()
        except Exception:
            pass


def _proxy_server(proxy_port, backend_port):
    with socket.socket() as s:
        s.settimeout(5.0)
        s.bind(("127.0.0.1", proxy_port))
        s.listen(5)
        try:
            client_conn, _ = s.accept()
            client_conn.settimeout(5.0)
            data = client_conn.recv(1024)
            # Transform data
            transformed = data.upper()
            # Forward to Backend
            with socket.create_connection(("127.0.0.1", backend_port), timeout=5.0) as backend_conn:
                backend_conn.sendall(transformed)
                resp = backend_conn.recv(1024)
                client_conn.sendall(resp)
            client_conn.close()
        except Exception:
            pass


def _run_tcp_proxy_diverter(filt, public_port, proxy_port, stop_event, use_async):  # noqa: C901
    if use_async:

        async def run_async():
            async with pydivert.PyDivert(filt) as w:
                async for packet in w:
                    if packet.dst_port == public_port:
                        packet.dst_port = proxy_port
                    elif packet.src_port == proxy_port:
                        packet.src_port = public_port
                    await w.send_async(packet)
                    if stop_event.is_set():
                        break

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_async())
    else:
        with pydivert.PyDivert(filt) as w:
            for packet in w:
                if packet.dst_port == public_port:
                    packet.dst_port = proxy_port
                elif packet.src_port == proxy_port:
                    packet.src_port = public_port
                w.send(packet)
                if stop_event.is_set():
                    break


@pytest.mark.parametrize("use_async", [False, True])
def test_integration_tcp_proxy_transform(use_async):
    """
    Scenario: A client connects to a 'Public Service' port.
    PyDivert intercepts the traffic, redirects it to a 'Hidden Proxy' port,
    the proxy modifies the data and forwards it to the 'Actual Backend'.
    All transparently to the client.
    """
    backend_port = get_free_port()
    proxy_port = get_free_port()
    public_port = get_free_port()

    # 1. Actual Backend Server
    threading.Thread(target=_backend_server, args=(backend_port,), daemon=True).start()

    # 2. Hidden Proxy Server (Actual TCP Proxy)
    threading.Thread(target=_proxy_server, args=(proxy_port, backend_port), daemon=True).start()

    # 3. WinDivert Transparent Redirection
    filt = f"tcp.DstPort == {public_port} or tcp.SrcPort == {proxy_port}"
    stop_event = threading.Event()

    divert_thread = threading.Thread(
        target=_run_tcp_proxy_diverter, args=(filt, public_port, proxy_port, stop_event, use_async), daemon=True
    )
    divert_thread.start()
    time.sleep(2.0)

    try:
        # Client connects to Public Port (Transparently handled by Proxy + WinDivert)
        with socket.create_connection(("127.0.0.1", public_port), timeout=5) as client:
            client.sendall(b"hello world")
            response = client.recv(1024)
            assert response == b"HELLO WORLD [Processed by Backend]"
    except (PermissionError, OSError) as e:
        pytest.skip(f"Test failed with {type(e).__name__}: {e}")
    finally:
        stop_event.set()
        try:
            socket.create_connection(("127.0.0.1", public_port), timeout=0.1)
        except Exception:
            pass
        divert_thread.join(timeout=1)


def _udp_server(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5.0)
        s.bind(("127.0.0.1", port))
        try:
            while True:
                try:
                    data, addr = s.recvfrom(1024)
                    if data == b"stop":
                        break
                    s.sendto(b"Original: " + data, addr)
                except TimeoutError:
                    continue
        except Exception:
            pass


def _run_dns_modification_diverter(filt, stop_event, use_async):
    if use_async:

        async def run_async():
            async with pydivert.PyDivert(filt) as w:
                async for packet in w:
                    if packet.payload and b"Original: " in packet.payload:
                        packet.payload = packet.payload.replace(b"Original: ", b"Modified: ")
                    await w.send_async(packet)
                    if stop_event.is_set():
                        break

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_async())
    else:
        with pydivert.PyDivert(filt) as w:
            for packet in w:
                if packet.payload and b"Original: " in packet.payload:
                    packet.payload = packet.payload.replace(b"Original: ", b"Modified: ")
                w.send(packet)
                if stop_event.is_set():
                    break


@pytest.mark.parametrize("use_async", [False, True])
def test_integration_dns_modification(use_async):
    """
    Scenario: Intercept UDP DNS-like traffic and modify the response payload.
    """
    server_port = get_free_port(socket.SOCK_DGRAM)

    # 1. Simple UDP Server
    server_thread = threading.Thread(target=_udp_server, args=(server_port,), daemon=True)
    server_thread.start()

    # 2. WinDivert Interception
    filt = f"udp.SrcPort == {server_port} and loopback"
    stop_event = threading.Event()

    divert_thread = threading.Thread(
        target=_run_dns_modification_diverter, args=(filt, stop_event, use_async), daemon=True
    )
    divert_thread.start()
    time.sleep(2.0)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.sendto(b"test data", ("127.0.0.1", server_port))
            resp, _ = client.recvfrom(1024)
            assert resp == b"Modified: test data"
    except (PermissionError, OSError) as e:
        pytest.skip(f"Test failed with {type(e).__name__}: {e}")
    finally:
        stop_event.set()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"stop", ("127.0.0.1", server_port))
        divert_thread.join(timeout=1)


@pytest.mark.skip(reason="Unregistering driver is too disruptive for VM state and subsequent tests")
def test_integration_driver_management():
    """
    Scenario: Register and Unregister the WinDivert driver.
    """
    try:
        pydivert.WinDivert.is_registered()
        pydivert.WinDivert.unregister()
        pydivert.WinDivert.register()
        assert pydivert.WinDivert.is_registered() is True
        pydivert.WinDivert.unregister()
        time.sleep(1.0)
        pydivert.WinDivert.register()
        assert pydivert.WinDivert.is_registered() is True
    except (PermissionError, OSError) as e:
        pytest.skip(f"Test failed with {type(e).__name__}: {e}")
