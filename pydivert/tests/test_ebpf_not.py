# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import pytest
from pydivert.filter import transpile_to_ebpf

def import_scapy():
    try:
        import scapy
        return True
    except ImportError:
        return False

def test_transpile_not_tcp():
    # not tcp -> should match all non-TCP protocols
    rules = transpile_to_ebpf("not tcp")
    # TCP is 6. not tcp should result in a rule where MATCH_PROTO is set and invert_mask has MATCH_PROTO
    found = False
    for r in rules:
        if r["match_mask"] & (1 << 4): # MATCH_PROTO
            if r["invert_mask"] & (1 << 4):
                if r["proto"] == 6:
                    found = True
    assert found

def test_transpile_not_equal():
    # ip.SrcAddr != 1.2.3.4
    rules = transpile_to_ebpf("ip.SrcAddr != 1.2.3.4")
    found = False
    import socket
    import struct
    target_ip = struct.unpack("!I", socket.inet_aton("1.2.3.4"))[0]
    
    for r in rules:
        if r["match_mask"] & (1 << 0): # MATCH_SRC_IP
            if r["invert_mask"] & (1 << 0):
                if r["src_ip"] == target_ip:
                    found = True
    assert found

def test_transpile_complex_not():
    # !(ip.SrcAddr == 1.1.1.1 && tcp.DstPort == 80)
    # De Morgan: ip.SrcAddr != 1.1.1.1 || tcp.DstPort != 80
    rules = transpile_to_ebpf("!(ip.SrcAddr == 1.1.1.1 && tcp.DstPort == 80)")
    assert len(rules) >= 2
    
    found_src = False
    found_dst = False
    for r in rules:
        if r["match_mask"] & (1 << 0) and r["invert_mask"] & (1 << 0):
            found_src = True
        if r["match_mask"] & (1 << 3) and r["invert_mask"] & (1 << 3):
            found_dst = True
    assert found_src
    assert found_dst

def test_transpile_not_not():
    # not not tcp == tcp
    rules = transpile_to_ebpf("not not tcp")
    found = False
    for r in rules:
        if r["match_mask"] & (1 << 4) and not (r["invert_mask"] & (1 << 4)):
            if r["proto"] == 6:
                found = True
    assert found

def test_transpile_not_loopback():
    # not loopback
    rules = transpile_to_ebpf("not loopback")
    found = False
    for r in rules:
        if r["match_mask"] & (1 << 6): # MATCH_LOOPBACK
            # Loopback doesn't use invert_mask, it just sets loopback=0
            if r["loopback"] == 0:
                found = True
    assert found

def test_transpile_not_syn():
    # not tcp.syn
    rules = transpile_to_ebpf("not tcp.syn")
    # This should generate rules. One of them should match TCP but NOT SYN.
    # Actually not (tcp AND syn) -> !tcp OR !syn
    found_not_syn = False
    for r in rules:
        if r["match_mask"] & (1 << 12): # MATCH_TCP_FLAGS
            if r["tcp_flags_mask"] & 0x02 and r["tcp_flags"] == 0:
                found_not_syn = True
    assert found_not_syn

@pytest.mark.skipif(not import_scapy(), reason="Scapy not installed")
def test_ebpf_not_equal_integration():
    import pydivert
    from scapy.all import IP, TCP, send
    import time
    import threading

    # Filter out our specific test port, but only for our specific source port
    # to avoid capturing background noise or replies.
    f = "tcp.SrcPort == 1000 and tcp.DstPort != 1234"
    with pydivert.Divert(f) as w:
        def send_packets():
            time.sleep(0.5)
            # This should be captured (port 80 != 1234, sport == 1000)
            send(IP(dst="127.0.0.1")/TCP(sport=1000, dport=80), verbose=False)
            # This should NOT be captured (port 1234 == 1234)
            send(IP(dst="127.0.0.1")/TCP(sport=1000, dport=1234), verbose=False)

        t = threading.Thread(target=send_packets)
        t.start()

        # We expect exactly one packet (from port 80)
        try:
            packet = w.recv(timeout=2)
            assert packet.dst_port == 80
            
            # Try to receive another one, should timeout
            try:
                extra = w.recv(timeout=1)
                pytest.fail(f"Captured unexpected packet: {extra}")
            except TimeoutError:
                pass
        finally:
            t.join()
