# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import socket
import threading
import time

from pydivert import PyDivert


def test_scenario_http_modify():
    """
    Scenario: Intercept an HTTP response and modify its content.
    """
    server_port = 8080

    def http_server():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", server_port))
            s.listen(1)
            while True:
                conn, addr = s.accept()
                with conn:
                    data = conn.recv(1024)
                    if not data:
                        break
                    response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"
                    conn.sendall(response)

    server_thread = threading.Thread(target=http_server, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    def http_modifier():
        try:
            with PyDivert(f"tcp.SrcPort == {server_port}") as w:
                for packet in w:
                    if packet.payload and b"Hello, World!" in packet.payload:
                        packet.payload = packet.payload.replace(b"World", b"PyDivert")
                        # Recalculate checksums is handled by send() by default
                    w.send(packet)
        except Exception:
            pass

    modifier_thread = threading.Thread(target=http_modifier, daemon=True)
    modifier_thread.start()
    time.sleep(1)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(5.0)
        client.connect(("127.0.0.1", server_port))
        client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        response = client.recv(1024)
        assert b"Hello, PyDivert!" in response
