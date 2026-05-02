import sys
# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import socket
import threading
import time
import pytest
from scapy.all import IP, TCP, ICMP, send, sniff, Raw
import pydivert
from pydivert.consts import Direction

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
            except socket.timeout:
                continue
            except Exception:
                break
        sock.close()

    thread = threading.Thread(target=run)
    thread.start()
    yield port
    stop_event.set()
    thread.join()

def test_scenario_drop_tcp(echo_server):
    """Scenario: Drop all TCP packets to a specific port."""
    port = echo_server
    filter_str = f"tcp.DstPort == {port}"
    
    # Start Divert and DON'T re-inject packets (effectively dropping them)
    def divert_and_drop():
        with pydivert.Divert(filter_str) as w:
            for packet in w:
                # Just receive and do nothing (drop)
                pass

    divert_thread = threading.Thread(target=divert_and_drop, daemon=True)
    divert_thread.start()
    time.sleep(1) # Wait for driver to hook

    # Try to connect - should fail or timeout
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        with pytest.raises((socket.timeout, ConnectionRefusedError, OSError)):
            s.connect(("127.0.0.1", port))

def test_scenario_modify_port(echo_server):
    """Scenario: Redirect traffic from Port A to Port B."""
    real_port = echo_server
    fake_port = 12345
    
    filter_str = f"tcp.DstPort == {fake_port} or tcp.SrcPort == {real_port}"
    
    def redirect_logic():
        with pydivert.Divert(filter_str) as w:
            for packet in w:
                if packet.tcp:
                    if packet.tcp.dst_port == fake_port:
                        packet.tcp.dst_port = real_port
                    elif packet.tcp.src_port == real_port:
                        packet.tcp.src_port = fake_port
                w.send(packet)

    divert_thread = threading.Thread(target=redirect_logic, daemon=True)
    divert_thread.start()
    time.sleep(1)

    # Connect to fake_port, should be redirected to real_port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        s.connect(("127.0.0.1", fake_port))
        s.sendall(b"hello")
        data = s.recv(1024)
        assert data == b"hello"

def test_scenario_sniff_icmp():
    """Scenario: Sniff ICMP (ping) without modification."""
    filter_str = "icmp"
    captured_packets = []

    def sniff_logic():
        with pydivert.Divert(filter_str) as w:
            for packet in w:
                captured_packets.append(packet)
                w.send(packet) # Pass through

    sniff_thread = threading.Thread(target=sniff_logic, daemon=True)
    sniff_thread.start()
    time.sleep(1)

    # Trigger some ICMP traffic
    if sys.platform.startswith("linux"):
        import os
        os.system("ping -c 1 127.0.0.1 > /dev/null 2>&1")
    else:
        ping_packet = IP(dst="127.0.0.1")/ICMP()
        raw_packet = bytes(ping_packet)
        
        with pydivert.Divert("false") as injector:
            p = pydivert.Packet(raw_packet, direction=Direction.OUTBOUND)
            injector.send(p)
    
    time.sleep(1)
    assert len(captured_packets) >= 1
    assert any(p.icmp for p in captured_packets)

def test_scenario_drop_flag(echo_server):
    """Scenario: Use Flag.DROP to silently drop packets in kernel."""
    port = echo_server
    from pydivert.consts import Flag
    
    with pydivert.Divert(f"tcp.DstPort == {port}", flags=Flag.DROP) as w:
        time.sleep(1)
        # Try to connect - should fail
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            with pytest.raises((socket.timeout, ConnectionRefusedError, OSError)):
                s.connect(("127.0.0.1", port))
        
        # Verify recv() yields nothing
        with pytest.raises(TimeoutError):
            w.recv(timeout=0.1)

def test_scenario_recv_only_flag():
    """Scenario: Use Flag.RECV_ONLY to disable packet injection."""
    from pydivert.consts import Flag
    with pydivert.Divert("false", flags=Flag.RECV_ONLY) as w:
        p = pydivert.Packet(b"E" + b"\x00" * 19) # dummy IP
        p.dst_addr = "127.0.0.1"
        with pytest.raises(OSError):
            w.send(p)
        
        # Also check async
        import asyncio
        with pytest.raises(OSError):
            asyncio.run(w.send_async(p))

def test_scenario_send_only_flag():
    """Scenario: Use Flag.SEND_ONLY to disable packet capture."""
    from pydivert.consts import Flag
    with pydivert.Divert("true", flags=Flag.SEND_ONLY) as w:
        with pytest.raises(OSError):
            w.recv(timeout=0.1)
        
        # Injection should still work
        p = pydivert.Packet(b"E" + b"\x00" * 19)
        p.dst_addr = "127.0.0.1"
        # This shouldn't raise OSError
        w.send(p)
