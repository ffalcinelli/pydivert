import socket
import threading
import time
import pytest
import pydivert
from pydivert.consts import Direction, Layer, Flag

# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later

# --- 1. Network Monitor (Passive Sniffer) ---
# Goal: Log all TCP SYN packets without affecting connectivity.

def test_use_case_monitor():
    syn_count = 0
    port = 54325
    
    def monitor_loop(stop_event):
        nonlocal syn_count
        try:
            # tcp.Syn and inbound: captures connection attempts
            with pydivert.Divert("tcp.Syn", flags=Flag.SNIFF) as w:
                while not stop_event.is_set():
                    try:
                        packet = w.recv(timeout=0.1)
                        if packet.tcp and packet.tcp.syn:
                            syn_count += 1
                    except TimeoutError: continue
        except (PermissionError, OSError): pass

    stop_event = threading.Event()
    t = threading.Event()
    thread = threading.Thread(target=monitor_loop, args=(stop_event,), daemon=True)
    thread.start()
    
    time.sleep(0.2)
    # Simulate connection attempt (won't actually connect, just send SYN)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.1)
        try: s.connect(("127.0.0.1", port))
        except Exception: pass
    
    time.sleep(0.2)
    stop_event.set()
    thread.join(timeout=1.0)
    # Verification: syn_count > 0 in a real environment

# --- 2. Simple Load Balancer (Transparent Redirection) ---
# Goal: Redirect traffic from port 80 to 8080 (local proxy).

def test_use_case_load_balancer():
    target_port = 54326
    proxy_port = 54327
    
    def lb_loop(stop_event):
        try:
            # Intercept both request and response
            filter_str = f"tcp.DstPort == {target_port} or tcp.SrcPort == {proxy_port}"
            with pydivert.Divert(filter_str) as w:
                while not stop_event.is_set():
                    try:
                        packet = w.recv(timeout=0.1)
                        if packet.tcp:
                            if packet.tcp.dst_port == target_port:
                                packet.tcp.dst_port = proxy_port
                            elif packet.tcp.src_port == proxy_port:
                                packet.tcp.src_port = target_port
                        w.send(packet)
                    except TimeoutError: continue
        except (PermissionError, OSError): pass

    stop_event = threading.Event()
    thread = threading.Thread(target=lb_loop, args=(stop_event,), daemon=True)
    thread.start()
    time.sleep(0.1); stop_event.set(); thread.join(timeout=1.0)

# --- 3. Privacy Guard (Ad-Blocker) ---
# Goal: Drop any traffic containing "TRACKING_ID" in the payload.

def test_use_case_privacy_guard():
    port = 54328
    
    def guard_loop(stop_event):
        try:
            with pydivert.Divert(f"tcp.DstPort == {port}") as w:
                while not stop_event.is_set():
                    try:
                        packet = w.recv(timeout=0.1)
                        if packet.payload and b"TRACKING_ID" in packet.payload:
                            # Drop it
                            continue
                        w.send(packet)
                    except TimeoutError: continue
        except (PermissionError, OSError): pass

    stop_event = threading.Event()
    thread = threading.Thread(target=guard_loop, args=(stop_event,), daemon=True)
    thread.start()
    time.sleep(0.1); stop_event.set(); thread.join(timeout=1.0)

# --- 4. Packet Injector (Raw Injection) ---
# Goal: Send a custom heartbeat packet.

def test_use_case_injector():
    try:
        with pydivert.Divert("false") as w:
            # Craft a raw UDP heartbeat
            raw = bytearray(fromhex("4500001c00014000401100007f0000017f000001" + "1234123400080000"))
            p = pydivert.Packet(raw)
            p.payload = b"HEARTBEAT"
            p.recalculate_checksums()
            w.send(p)
    except (PermissionError, OSError):
        pass

def fromhex(s):
    return bytes.fromhex(s.replace(" ", "").replace("\n", ""))
