# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import socket
import threading
import time

from pydivert import PyDivert


def _run_http_server(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(1)
        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024)
                if not data:
                    break
                response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"
                conn.sendall(response)


def _run_http_modifier(port, stop_event):
    try:
        with PyDivert(f"tcp.SrcPort == {port}") as w:
            for packet in w:
                if stop_event.is_set():
                    break
                if packet.payload and b"Hello, World!" in packet.payload:
                    packet.payload = packet.payload.replace(b"World", b"PyDivert")
                w.send(packet)
    except Exception as e:
        if not stop_event.is_set():
            print(f"Modifier error: {e}")


def test_scenario_http_modify():
    """
    Scenario: Intercept an HTTP response and modify its content.
    """
    server_port = 8080
    server_thread = threading.Thread(target=_run_http_server, args=(server_port,), daemon=True)
    server_thread.start()
    time.sleep(0.5)

    stop_event = threading.Event()
    modifier_thread = threading.Thread(target=_run_http_modifier, args=(server_port, stop_event), daemon=True)
    modifier_thread.start()
    time.sleep(1)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(5.0)
            client.connect(("127.0.0.1", server_port))
            client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = client.recv(1024)
            assert b"Hello, PyDivert!" in response
    finally:
        stop_event.set()
        # Trigger one more packet to unblock recv if it's stuck
        try:
            with socket.socket() as s:
                s.settimeout(0.1)
                s.connect(("127.0.0.1", server_port))
        except (TimeoutError, OSError):
            pass
        modifier_thread.join(timeout=1.0)
