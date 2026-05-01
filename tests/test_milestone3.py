# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import pytest
import socket
from pydivert.filter import transpile_to_ebpf
from pydivert.packet import Packet

def test_transpiler_extended_fields():
    # Test TTL transpilation
    rules = transpile_to_ebpf("ip.TTL == 64")
    assert len(rules) == 1
    assert rules[0]["ttl"] == 64
    assert rules[0]["match_mask"] & (1 << 11) # MATCH_TTL
    
    # Test TCP Syn flag transpilation
    rules = transpile_to_ebpf("tcp.Syn")
    assert len(rules) == 1
    assert rules[0]["tcp_flags"] == 0x02 # SYN bit
    assert rules[0]["tcp_flags_mask"] == 0x02
    assert rules[0]["match_mask"] & (1 << 12) # MATCH_TCP_FLAGS

def test_jit_fallback_logic():
    from pydivert.jit import compile_filter
    from pydivert.filter import transpile_to_python
    
    # A filter that is valid but complex
    filter_str = "tcp.SrcPort == 1234 and ip.TTL < 128"
    python_expr = transpile_to_python(filter_str)
    jit_func = compile_filter(python_expr)
    
    # Create matching packet
    raw_match = bytearray(b'E\x00\x00\x28\x00\x01\x00\x00@\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01')
    raw_match += b'\x04\xd2\x00P\x00\x00\x00\x01\x00\x00\x00\x02P\x02\x04\x00\x00\x00\x00\x00'
    p_match = Packet(raw_match)
    assert jit_func(p_match) is True
    
    # Create non-matching packet (different TTL)
    raw_no_match = bytearray(raw_match)
    raw_no_match[8] = 200 # TTL = 200
    p_no_match = Packet(raw_no_match)
    assert jit_func(p_no_match) is False

import sys
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Kernel test for Linux")
def test_kernel_ttl_matching():
    import pydivert
    from scapy.all import IP, UDP, send
    import time
    
    try:
        # Open a handle with TTL filter
        with pydivert.Divert("ip.TTL == 63", flags=pydivert.Flag.SNIFF) as w:
            time.sleep(0.5)
            # Send a packet with TTL 63 using Scapy
            packet = IP(dst="127.0.0.1", ttl=63)/UDP(sport=1234, dport=5678)
            send(packet, verbose=False, iface="lo")
            
            # Wait for capture
            captured = w.recv(timeout=2.0)
            assert captured.ip.ttl == 63
    except (ImportError, PermissionError):
        pytest.skip("EBPF/Scapy not available or permission denied")
