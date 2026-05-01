# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys
import pytest
import pydivert
from pydivert.consts import Layer, Flag

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="eBPF only supported on Linux")

def test_ebpf_init_errors():
    from pydivert.ebpf import EBPFDivert
    # Test missing libbpf (simulated by mocking)
    import pydivert.ebpf
    orig_libbpf = pydivert.ebpf.libbpf
    pydivert.ebpf.libbpf = None
    try:
        with pytest.raises(ImportError, match="libbpf missing"):
            EBPFDivert()
    finally:
        pydivert.ebpf.libbpf = orig_libbpf

def test_ebpf_open_close():
    with pydivert.Divert("false") as w:
        assert w.is_open
        with pytest.raises(RuntimeError, match="already open"):
            w.open()
    
    assert not w.is_open
    with pytest.raises(RuntimeError, match="not open"):
        w.close()
    
    with pytest.raises(RuntimeError, match="not open"):
        w.recv()

@pytest.mark.asyncio
async def test_ebpf_async():
    with pydivert.Divert("false") as w:
        # We don't expect any packets for "false" filter
        with pytest.raises(TimeoutError):
            await w.recv_async(timeout=0.1)

def test_ebpf_invalid_interface():
    from pydivert.ebpf import EBPFDivert
    w = EBPFDivert()
    w._ifname = "invalid_if_name_123"
    with pytest.raises((OSError, RuntimeError)):
        w.open()

def test_ebpf_send_errors():
    with pydivert.Divert("false") as w:
        p = pydivert.Packet(b"E" + b"\x00" * 19) # dummy IP
        p.dst_addr = "127.0.0.1"
        # Recalculate checksums might fail on bogus packet but should not crash
        w.send(p, recalculate_checksum=True)
        
        # Test ipv6 send error if ipv6 sock not available
        p6 = pydivert.Packet(b"`" + b"\x00" * 39) # dummy IPv6
        p6.dst_addr = "::1"
        orig_sock6 = w._impl._raw_sock6
        w._impl._raw_sock6 = None
        # Mocking an ipv6 packet properly for the property
        p6._address_family = socket.AF_INET6
        with pytest.raises(OSError, match="IPv6 raw socket not available"):
            w.send(p6)
        w._impl._raw_sock6 = orig_sock6

import socket # needed for AF_INET6

def test_ebpf_flags():
    # Test flags
    with pydivert.Divert("false", flags=Flag.SNIFF) as w:
        assert w.is_open
    
    with pydivert.Divert("false", flags=Flag.DROP) as w:
        assert w.is_open

def test_ebpf_supported_layers():
    # Test supported layers (now including FLOW and SOCKET)
    for layer in [Layer.NETWORK, Layer.FLOW, Layer.SOCKET]:
        with pydivert.Divert("false", layer=layer) as w:
            assert w.is_open

def test_ebpf_unsupported_layer():
    # Test truly unsupported layer
    with pytest.raises(NotImplementedError, match="not supported on Linux"):
        pydivert.Divert("false", layer=Layer.REFLECT)

def test_ebpf_close_cleanup():
    w = pydivert.Divert("false")
    w.open()
    # Mocking missing attributes to test hasattr checks in close()
    impl = w._impl
    del impl._hook_ingress
    del impl._hook_egress
    w.close()
    assert not w.is_open
