# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import pytest
import pydivert
import socket
import time
from pydivert.packet import Packet

def test_zerocopy_parsing_ipv4():
    # Construct a raw IPv4/UDP packet
    # Version=4, IHL=5, TOS=0, Len=28, ID=1, Frag=0, TTL=64, Proto=17, Checksum=0, SRC=127.0.0.1, DST=127.0.0.1
    raw = bytearray(b'E\x00\x00\x1c\x00\x01\x00\x00@\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01')
    # UDP: Sport=1234, Dport=80, Len=8, Check=0
    raw += b'\x04\xd2\x00P\x00\x08\x00\x00'
    
    p = Packet(raw)
    assert p.ipv4 is not None
    assert p.src_addr == "127.0.0.1"
    assert p.dst_addr == "127.0.0.1"
    assert p.src_port == 1234
    assert p.dst_port == 80
    
    # Verify zero-copy modification
    p.src_addr = "10.0.0.1"
    assert raw[12:16] == socket.inet_pton(socket.AF_INET, "10.0.0.1")
    
    p.src_port = 8888
    assert raw[20:22] == b'\x22\xb8' # 8888 in hex

def test_zerocopy_parsing_tcp():
    # IPv4 + TCP
    raw = bytearray(b'E\x00\x00(\x00\x01\x00\x00@\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01')
    # TCP: Sport=1234, Dport=80, Seq=1, Ack=2, Off=5, Flags=SYN, Win=1024, Check=0, Urg=0
    raw += b'\x04\xd2\x00P\x00\x00\x00\x01\x00\x00\x00\x02P\x02\x04\x00\x00\x00\x00\x00'
    
    p = Packet(raw)
    assert p.tcp is not None
    assert p.tcp.seq_num == 1
    assert p.tcp.syn is True
    assert p.tcp.ack is False
    
    p.tcp.seq_num = 100
    assert raw[24:28] == b'\x00\x00\x00d' # 100 in hex

@pytest.mark.skipif(not socket.gethostname().startswith("linux") and not socket.gethostname().startswith("ubuntu"), reason="Batching test optimized for Linux VM")
def test_batch_receive_ebpf():
    # Use EBPFDivert directly if on linux
    from pydivert.ebpf import EBPFDivert
    try:
        with EBPFDivert("false") as w:
            # Inject fake packets into the internal queue to test batch draining
            p1 = Packet(b"E" + b"\x00" * 27)
            p2 = Packet(b"E" + b"\x00" * 27)
            w._impl._queue.extend([p1, p2])
            
            batch = w.recv_batch(count=2, timeout=0.1)
            assert len(batch) == 2
    except (ImportError, PermissionError):
        pytest.skip("EBPF not available or permission denied")

def test_performance_comparison():
    # Construct a packet
    raw = bytearray(b'E\x00\x00\x1c\x00\x01\x00\x00@\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01')
    raw += b'\x04\xd2\x00P\x00\x08\x00\x00'
    p = Packet(raw)
    
    start = time.perf_counter()
    for _ in range(10000):
        _ = p.src_addr
        _ = p.dst_port
    end = time.perf_counter()
    
    duration = end - start
    print(f"\nZero-copy parsing duration for 10k accesses: {duration:.4f}s")
    # This should be very fast (< 0.1s typically)
    assert duration < 1.0 
