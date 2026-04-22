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
Integration tests for PyDivert using a local HTTP server.
These tests verify that PyDivert can correctly intercept and modify HTTP traffic.
Note: These tests must be run on Windows with administrator privileges.
"""

import asyncio
import socket
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

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
        if os.environ.get("GITHUB_ACTIONS"):
            if sys.platform == "darwin" and getattr(e, "errno", None) == 22:
                pytest.skip(f"Divert sockets are not supported on this macOS version: {e}")
            pytest.fail(f"PyDivert integration tests must run in CI, but initialization failed: {e}")
        pytest.skip(f"PyDivert not available: {e}")


def get_free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run_http_redirection_diverter(filt, fake_port, real_port, stop_event, use_async):  # noqa: C901
    if use_async:
        async def run_async():
            async with pydivert.PyDivert(filt) as w:
                async for packet in w:
                    if packet.dst_port == fake_port:
                        packet.dst_port = real_port
                    elif packet.src_port == real_port:
                        packet.src_port = fake_port
                    await w.send_async(packet)
                    if stop_event.is_set():
                        break
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_async())
    else:
        with pydivert.PyDivert(filt) as w:
            for packet in w:
                if packet.dst_port == fake_port:
                    packet.dst_port = real_port
                elif packet.src_port == real_port:
                    packet.src_port = fake_port
                w.send(packet)
                if stop_event.is_set():
                    break


@pytest.mark.parametrize("use_async", [False, True])
def test_http_port_redirection(use_async):  # noqa: C901
    class SimpleHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Port Redirection Success")

        def log_message(self, format, *args):
            pass

    # Real port where the server is listening
    httpd = HTTPServer(("127.0.0.1", 0), SimpleHandler)
    real_port = httpd.server_address[1]

    def serve():
        try:
            httpd.serve_forever()
        except OSError:
            pass

    server_thread = threading.Thread(target=serve)
    server_thread.daemon = True
    server_thread.start()

    # Fake port that the client will connect to
    fake_port = get_free_port()
    while fake_port == real_port:
        fake_port = get_free_port()

    filt = f"(tcp.DstPort == {fake_port} or tcp.SrcPort == {real_port})"
    stop_event = threading.Event()

    divert_thread = threading.Thread(
        target=_run_http_redirection_diverter,
        args=(filt, fake_port, real_port, stop_event, use_async),
        daemon=True
    )
    divert_thread.start()

    time.sleep(2.0)
    try:
        url = f"http://127.0.0.1:{fake_port}/"
        with urllib.request.urlopen(url, timeout=10) as response:
            body = response.read()
            assert body == b"Port Redirection Success"
    finally:
        stop_event.set()
        try:
            with socket.create_connection(("127.0.0.1", fake_port), timeout=0.1) as s:
                s.close()
        except OSError:
            pass
        httpd.shutdown()
        divert_thread.join(timeout=1)


def _run_http_modification_diverter(filt, stop_event, use_async):
    if use_async:
        async def run_async():
            async with pydivert.PyDivert(filt) as w:
                async for packet in w:
                    if packet.payload and b"Hello, World!" in packet.payload:
                        packet.payload = packet.payload.replace(b"Hello", b"PyDiv")
                    await w.send_async(packet)
                    if stop_event.is_set():
                        break
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_async())
    else:
        with pydivert.PyDivert(filt) as w:
            for packet in w:
                if packet.payload and b"Hello, World!" in packet.payload:
                    packet.payload = packet.payload.replace(b"Hello", b"PyDiv")
                w.send(packet)
                if stop_event.is_set():
                    break


@pytest.mark.parametrize("use_async", [False, True])
def test_http_modification(use_async):  # noqa: C901
    class SimpleHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Hello, World!")

        def log_message(self, format, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), SimpleHandler)
    port = httpd.server_address[1]

    def serve():
        try:
            httpd.serve_forever()
        except OSError:
            pass

    server_thread = threading.Thread(target=serve)
    server_thread.daemon = True
    server_thread.start()

    filt = f"(tcp.DstPort == {port} or tcp.SrcPort == {port})"
    stop_event = threading.Event()

    divert_thread = threading.Thread(
        target=_run_http_modification_diverter,
        args=(filt, stop_event, use_async),
        daemon=True
    )
    divert_thread.start()

    time.sleep(2.0)
    try:
        url = f"http://127.0.0.1:{port}/"
        with urllib.request.urlopen(url, timeout=10) as response:
            body = response.read()
            assert body == b"PyDiv, World!"
    finally:
        stop_event.set()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1) as s:
                s.close()
        except OSError:
            pass
        httpd.shutdown()
        divert_thread.join(timeout=1)
