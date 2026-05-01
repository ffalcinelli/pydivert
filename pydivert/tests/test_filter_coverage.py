# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import pytest
from pydivert.filter import transpile_to_ebpf

def test_transpiler_basic():
    # Test common filter strings
    filters = [
        "tcp",
        "udp",
        "icmp",
        "ip",
        "ip.SrcAddr == 127.0.0.1",
        "ip.DstAddr == 1.2.3.4",
        "tcp.SrcPort == 80",
        "tcp.DstPort == 443",
        "udp.SrcPort == 53",
        "udp.DstPort == 53",
        "tcp.SrcPort == 80 or tcp.DstPort == 80",
        "ip.SrcAddr == 127.0.0.1 and tcp.SrcPort == 80",
        "true",
        "ipv6",
        "ipv6.SrcAddr == ::1",
        "ipv6.DstAddr == 2001:db8::1"
    ]
    for f in filters:
        rules = transpile_to_ebpf(f)
        assert isinstance(rules, list)

def test_transpiler_errors():
    # Test supported filters (no longer raising)
    assert isinstance(transpile_to_ebpf("outbound"), list)
    assert isinstance(transpile_to_ebpf("loopback"), list)
    assert isinstance(transpile_to_ebpf("false"), list)

    # Test invalid syntax
    with pytest.raises(Exception):
        transpile_to_ebpf("something bogus")

def test_normalize_filter():
    from pydivert.filter import normalize_filter
    assert "ip.SrcAddr" in normalize_filter("ip.src == 127.0.0.1")
    assert "tcp.SrcPort" in normalize_filter("tcp.port == 80")
    assert "true" == normalize_filter("true")
    assert "(ip.SrcAddr == 1.1.1.1 || ip.DstAddr == 1.1.1.1)" in normalize_filter("ip.addr == 1.1.1.1")

def test_transpile_to_python():
    from pydivert.filter import transpile_to_python
    expr = transpile_to_python("tcp and tcp.DstPort == 80")
    assert "packet.tcp" in expr
    assert "packet.dst_port == 80" in expr
    
    assert "True" == transpile_to_python("true")
    assert "False" == transpile_to_python("false")
    assert "not" in transpile_to_python("not tcp")
    assert "if" in transpile_to_python("tcp ? 1 : 0")
    assert "AggregateField" in transpile_to_python("ip.addr == 1.1.1.1")


def test_transpiler_edge_cases():
    # Test complex combinations
    f = "(tcp.SrcPort == 80 or tcp.SrcPort == 443) and ip.SrcAddr == 1.1.1.1"
    rules = transpile_to_ebpf(f)
    assert len(rules) >= 1
