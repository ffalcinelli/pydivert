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

import http.server
import socket
import threading
import time
import urllib.request

import pydivert


def get_free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_http_port_redirection():
    class SimpleHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Port Redirection Success")

        def log_message(self, format, *args):
            pass

    # Real port where the server is listening
    httpd = http.server.HTTPServer(("127.0.0.1", 0), SimpleHandler)
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

    # Filter to capture:
    # 1. Inbound to fake_port (to redirect to real_port)
    # 2. Outbound from real_port (to redirect back to fake_port)
    filt = f"(tcp.DstPort == {fake_port} or tcp.SrcPort == {real_port})"

    stop_event = threading.Event()

    def divert_and_redirect():
        with pydivert.WinDivert(filt) as w:
            for packet in w:
                if stop_event.is_set():
                    break

                # Client -> Fake Port: Redirect to Real Port
                if packet.dst_port == fake_port:
                    packet.dst_port = real_port
                # Server -> Client: Redirect Source Port back to Fake Port
                elif packet.src_port == real_port:
                    packet.src_port = fake_port

                w.send(packet)

    divert_thread = threading.Thread(target=divert_and_redirect)
    divert_thread.start()

    # Give some time for WinDivert to start
    time.sleep(1.0)
    try:
        # Client connects to the FAKE port
        url = f"http://127.0.0.1:{fake_port}/"
        with urllib.request.urlopen(url, timeout=5) as response:
            body = response.read()
            assert body == b"Port Redirection Success"
    finally:
        stop_event.set()
        # Unblock WinDivert loop
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{fake_port}/", timeout=0.1)
        except OSError:
            pass

        httpd.shutdown()
        divert_thread.join(timeout=1)


def test_http_modification():
    class SimpleHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Hello, World!")

        def log_message(self, format, *args):
            pass

    # Bind to 127.0.0.1:0 to get a random free port
    httpd = http.server.HTTPServer(("127.0.0.1", 0), SimpleHandler)
    port = httpd.server_address[1]

    def serve():
        try:
            httpd.serve_forever()
        except OSError:
            pass

    server_thread = threading.Thread(target=serve)
    server_thread.daemon = True
    server_thread.start()

    # WinDivert filter for our HTTP server port
    # We want to capture packets going to or coming from the server port
    # For loopback, capturing outbound is sufficient and avoids double-processing.
    filt = f"(tcp.DstPort == {port} or tcp.SrcPort == {port})"

    # Event to stop the diverter thread
    stop_event = threading.Event()

    def divert_and_modify():
        with pydivert.WinDivert(filt) as w:
            for packet in w:
                if stop_event.is_set():
                    break

                # Check if the packet contains our target string
                if packet.payload and b"Hello, World!" in packet.payload:
                    packet.payload = packet.payload.replace(b"Hello", b"PyDiv")

                w.send(packet)

    divert_thread = threading.Thread(target=divert_and_modify)
    divert_thread.start()

    # Give some time for WinDivert to start
    time.sleep(1.0)
    try:
        url = f"http://127.0.0.1:{port}/"
        with urllib.request.urlopen(url, timeout=5) as response:
            body = response.read()
            assert body == b"PyDiv, World!"
    finally:
        stop_event.set()
        # To unblock the 'for packet in w' loop, we might need to send a dummy packet
        # or just wait for it to time out if we used a timeout.
        # However, WinDivert's recv is blocking by default.
        # A simple way to unblock it is to make one more request that will be captured.
        try:
            urllib.request.urlopen(url, timeout=0.1)
        except OSError:
            pass

        httpd.shutdown()
        divert_thread.join(timeout=1)
