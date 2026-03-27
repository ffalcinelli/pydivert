# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Integration tests for PyDivert using a local HTTP server.
These tests verify that PyDivert can correctly intercept and modify HTTP traffic.
Note: These tests must be run on Windows with administrator privileges.
"""

import http.server
import threading
import urllib.request
import pydivert
import time

def test_http_modification():
    class SimpleHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Hello, World!")
            
        def log_message(self, format, *args):
            pass

    # Bind to 127.0.0.1:0 to get a random free port
    httpd = http.server.HTTPServer(('127.0.0.1', 0), SimpleHandler)
    port = httpd.server_address[1]
    
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    # WinDivert filter for our HTTP server port
    # We want to capture packets going to or coming from the server port
    filt = f"tcp.DstPort == {port} or tcp.SrcPort == {port}"
    
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
    time.sleep(0.5)

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
        except:
            pass
        
        httpd.shutdown()
        divert_thread.join(timeout=1)
