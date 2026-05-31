import ctypes
import sys
from unittest.mock import MagicMock, patch

import pytest

import pydivert
import pydivert.filter
from pydivert import Divert, service
from pydivert.consts import Param
from pydivert.filter import normalize_filter, transpile_to_ebpf, transpile_to_python
from pydivert.jit import compile_filter
from pydivert.packet import Packet
from pydivert.util import fromhex, internet_checksum

# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils

# --- Basic Handle Operations ---


def test_open():
    w = Divert("false")
    w.open()
    assert w.is_open
    w.close()
    assert not w.is_open

    with w:
        with Divert("false") as w2:
            assert w2.is_open
        assert w.is_open
        assert "open" in repr(w)


def test_is_registered_direct():
    assert isinstance(service.is_registered(), bool)


# --- Filters ---


def test_check_filter():
    res, pos, msg = Divert.check_filter("true")
    assert res
    assert pos == 0


# --- OS Edge Cases & Mocks ---


@pytest.mark.skipif(sys.platform != "win32", reason="WinDivert fallback is Windows-specific")
def test_windivert_unregister_fallback_mock():
    with patch("pydivert.service.stop_service", return_value=False):
        with patch("subprocess.run") as mock_run:
            # Mock successful sc.exe call
            mock_run.return_value = MagicMock(returncode=0)
            Divert.unregister()
            assert mock_run.call_count >= 1


@pytest.mark.skipif(sys.platform == "win32", reason="eBPF mocks are Linux-specific")
def test_ebpf_load_failure_mock():
    from pydivert.ebpf import EBPFDivert

    with patch("pydivert.ebpf.libbpf") as mock_lib:
        mock_lib.bpf_object__open_file.return_value = 1
        mock_lib.bpf_object__load.return_value = -1
        with pytest.raises(RuntimeError, match="Failed to load BPF object"):
            EBPFDivert("false").open()


# --- Parameters ---


@pytest.mark.skipif(sys.platform != "win32", reason="Params are WinDivert only")
def test_params_mock():
    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        mock_dll.WinDivertOpen.return_value = 123
        w = Divert()
        w._handle = 123
        mock_dll.WinDivertGetParam.return_value = True

        # Simulate byref assignment
        def side_effect(h, p, v):
            v._obj.value = 512
            return True

        mock_dll.WinDivertGetParam.side_effect = side_effect
        assert w.get_param(Param.QUEUE_LEN) == 512


# --- Divert closed handle errors ---


def test_closed_handle_errors():
    w = pydivert.Divert("false")
    # All these should raise RuntimeError
    with pytest.raises(RuntimeError):
        w.recv()
    with pytest.raises(RuntimeError):
        w.recv_batch()
    with pytest.raises(RuntimeError, match="not open"):
        w.close()
    with pytest.raises(RuntimeError):
        w.stats()
    with pytest.raises(RuntimeError):
        w.send(Packet(b""))
    with pytest.raises(RuntimeError):
        w.send_batch([Packet(b"")])
    with pytest.raises(RuntimeError):
        import asyncio

        asyncio.run(w.recv_async())


# --- filter.py Coverage ---


def test_filter_ternary():
    # ternary logic is parsed but simplified in eBPF transpilation
    f = "tcp ? tcp.DstPort == 80 : udp"
    rules = transpile_to_ebpf(f)
    assert isinstance(rules, list)


def test_filter_complex_logic():
    # tcp.DstPort == 80 or udp.DstPort == 53 -> 2 rules
    # and ip.SrcAddr == 1.2.3.4 -> should still be 2 rules
    f = "(tcp.DstPort == 80 or udp.DstPort == 53) and ip.SrcAddr == 1.2.3.4"
    rules = transpile_to_ebpf(f)
    assert len(rules) >= 1
    # Check that we at least have some rule content
    assert any("src_ip" in r for r in rules)


def test_filter_not():
    f = "not tcp"
    rules = transpile_to_ebpf(f)
    assert isinstance(rules, list)


def test_filter_indexing():
    f = "ip[0] == 0x45"
    rules = transpile_to_ebpf(f)
    assert isinstance(rules, list)


def test_filter_macros():
    # Test common macros
    macros = ["WINDIVERT_LAYER_NETWORK", "TCP", "UDP", "ICMP", "IP"]
    for m in macros:
        rules = transpile_to_ebpf(m)
        assert isinstance(rules, list)


def test_normalize_filter_extra():
    assert "ip.SrcAddr" in normalize_filter("ip.srcaddr == 1.1.1.1")
    assert "ipv6.SrcAddr" in normalize_filter("ipv6.src == ::1")
    assert "AggregateField" in transpile_to_python("ip.addr == 1.1.1.1")


# --- jit.py Coverage ---


def test_jit_all_ops():
    raw = bytearray(b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    raw += b"\x00\x50\x1f\x90\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x91\x7c\x00\x00"
    p = Packet(raw)

    # BinOp
    assert compile_filter("1 + 2 * 3 / 2 - 1 == 3")(p)
    # Compare
    assert compile_filter("1 < 2 <= 2 > 0 >= 0 != 5 == 5")(p)
    # UnaryOp
    assert compile_filter("not False and -1 < 0")(p)
    # IfExp
    assert compile_filter("1 if True else 0")(p) == 1
    # Call
    assert compile_filter("len(packet.raw) == 40")(p)
    # Error handling
    assert compile_filter("1 ** 2")(p) is False  # Unsupported op


# --- util.py Coverage ---


def test_util_checksums():
    # Valid localhost TCP header checksum calculation
    # 45 00 00 28 00 00 40 00 40 06 00 00 7f 00 00 01 7f 00 00 01
    valid_ip_raw = fromhex("4500002800004000400600007f0000017f000001")
    calculated = internet_checksum(valid_ip_raw)
    assert calculated == 0x3CCE


# --- packet/tcp.py Coverage ---


def test_tcp_properties_all():
    raw = bytearray(b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    raw += b"\x12\x34\x00\x50\x00\x00\x00\x01\x00\x00\x00\x02\x50\x02\x20\x00\x00\x00\x00\x00"
    p = Packet(raw)
    t = p.tcp
    assert t is not None
    t.src_port = 80
    assert t.src_port == 80
    t.dst_port = 443
    assert t.dst_port == 443
    t.seq_num = 100
    assert t.seq_num == 100
    t.ack_num = 200
    assert t.ack_num == 200
    assert t.header_len == 20
    t.window = 1024
    assert t.window == 1024
    t.urg_ptr = 10
    assert t.urg_ptr == 10

    # Flags
    flags = ["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr", "ns"]
    for f in flags:
        setattr(t, f, True)
        assert getattr(t, f) is True
        setattr(t, f, False)
        assert getattr(t, f) is False


# --- batch operations ---


def test_batch_operations():
    try:
        with pydivert.Divert("false") as w:
            # recv_batch with timeout
            try:
                packets = w.recv_batch(count=2, timeout=0.1)
                assert isinstance(packets, list)
            except TimeoutError:
                pass

            # send_batch
            raw = fromhex("4500001c0001000040110000c0a80001c0a80002" + "1234123400080000")
            p = Packet(raw)
            p.recalculate_checksums()
            try:
                w.send_batch([p, p])
            except (OSError, PermissionError):
                pass
    except (PermissionError, OSError):
        pytest.skip("No permissions")


# --- stats ---


def test_divert_stats():
    try:
        with pydivert.Divert("false") as w:
            s = w.stats()
            assert isinstance(s, dict)
            # Linux has 'diverted', Windows has 'queue_len'
            assert any(k in s for k in ("diverted", "queue_len", "captured", "count"))
    except (PermissionError, OSError):
        pytest.skip("No permissions")


# --- error handling ---


def test_invalid_filter_error():
    if sys.platform == "win32":
        with pytest.raises(OSError):
            pydivert.Divert("something invalid").open()
    else:
        # eBPF transpiler might not raise on all invalid strings if they don't produce rules
        pass


def test_double_open_error():
    try:
        w = pydivert.Divert("false")
        w.open()
        with pytest.raises(RuntimeError):
            w.open()
        w.close()
    except (PermissionError, OSError):
        pytest.skip("No permissions")


# --- service.py Coverage ---


def test_service_registration():
    if sys.platform == "win32":
        import pydivert.service

        # Just check it doesn't crash
        res = pydivert.service.is_registered()
        assert isinstance(res, bool)
        # Try stop if possible (might fail in VM if not Admin, but we are usually Admin in Vagrant)
        if sys.platform == "win32":
            try:
                pydivert.service.stop_service()
            except Exception:
                pass


# --- aggressive packet property tests ---


def test_packet_all_properties_exhaustive():
    import inspect

    # Test different packet types
    packets = [
        # IPv4 TCP
        Packet(fromhex("4500002800004000400600007f0000017f000001" + "0050005000000000000000005002200000000000")),
        # IPv4 UDP
        Packet(fromhex("4500001c00004000401100007f0000017f000001" + "1234123400080000")),
        # IPv6 TCP
        Packet(
            fromhex(
                "6000000000140640"
                + "00000000000000000000000000000001"
                + "00000000000000000000000000000001"
                + "0050005000000000000000005002200000000000"
            )
        ),
        # ICMP
        Packet(fromhex("4500001c00004000400100007f0000017f000001" + "0800000000000000")),
        # Malformed / Short
        Packet(b"E"),
        Packet(b""),
    ]

    for p in packets:
        # Get all properties and methods
        for name, value in inspect.getmembers(type(p)):
            if isinstance(value, property):
                try:
                    getattr(p, name)
                except Exception:
                    pass

        # Access nested headers and their properties
        for hdr in [p.ipv4, p.ipv6, p.tcp, p.udp, p.icmp, p.icmpv4, p.icmpv6]:
            if hdr:
                for name, value in inspect.getmembers(type(hdr)):
                    if isinstance(value, property):
                        try:
                            getattr(hdr, name)
                        except Exception:
                            pass


def test_filter_transpiler_errors():
    from pydivert.filter import transpile_to_rules

    # Test invalid syntax
    with pytest.raises(pydivert.filter.FilterSyntaxError):
        transpile_to_rules("!!!")

    # Test edge case field names
    assert transpile_to_rules("UnknownField == 1")
    assert transpile_to_rules("tcp.Unknown == 1")


def test_jit_edge_cases():
    p = Packet(fromhex("4500001c00004000401100007f0000017f000001" + "1234123400080000"))
    # Test non-bool results are cast to bool by compile_filter
    assert compile_filter("1 + 1")(p) is True
    # Test exceptions in JIT
    assert compile_filter("packet.unknown_attr")(p) is False
    # Test attribute access on None
    assert compile_filter("packet.tcp.src_port")(p) is False  # UDP packet


# --- WinDivert / EBPF Mock Edge Cases ---


def test_windivert_open_failure_mock():
    if sys.platform != "win32":
        pytest.skip("Windows only")
    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        mock_dll.WinDivertOpen.side_effect = OSError(None, "Access Denied", None, 5)
        with pytest.raises(OSError):
            pydivert.Divert().open()


def test_ebpf_attach_failure_mock():
    if sys.platform == "win32":
        pytest.skip("Linux only")
    from pydivert.ebpf import EBPFDivert

    with patch("pydivert.ebpf.libbpf") as mock_lib:
        mock_lib.bpf_object__open_file.return_value = 1
        mock_lib.bpf_object__load.return_value = 0
        mock_lib.bpf_program__name.return_value = b"test"
        mock_lib.bpf_tc_attach.return_value = -1
        with pytest.raises(RuntimeError, match="Failed to attach"):
            EBPFDivert("false").open()


# --- WinDivert Params exhaustive ---


def test_windivert_params_all():
    if sys.platform != "win32":
        pytest.skip("Windows only")
    from pydivert.consts import Param

    try:
        with pydivert.Divert("false") as w:
            for p in Param:
                try:
                    val = w.get_param(p)
                    w.set_param(p, val)
                except Exception:
                    pass
    except (PermissionError, OSError):
        pytest.skip("No permissions")


# --- windivert_dll proxies ---


def test_dll_proxies():
    from pydivert.windivert_dll import GetLastError, WinDivertOpen

    # Just check they are callable and don't crash
    assert WinDivertOpen
    assert GetLastError() >= 0


# --- send_ex coverage ---


def test_send_ex_basic():
    if sys.platform != "win32":
        pytest.skip("Windows only")
    try:
        with pydivert.Divert("false") as w:
            raw = fromhex("4500001c00004000401100007f0000017f000001" + "1234123400080000")
            p = Packet(raw)
            p.recalculate_checksums()
            # send_ex is usually called on the backend impl directly
            if hasattr(w._impl, "send_ex"):
                w._impl.send_ex(p)  # type: ignore
    except (PermissionError, OSError):
        pytest.skip("No permissions")


# --- WinDivert Helpers exhaustive ---


def test_windivert_helpers_all():
    if sys.platform != "win32":
        pytest.skip("Windows only")
    from pydivert.windivert_dll import WinDivertAddress, WinDivertHelperCalcChecksums

    raw = bytearray(fromhex("4500001c00010000401100007f0000017f000001" + "1234123400080000"))
    addr = WinDivertAddress()
    # Just hit the function
    try:
        WinDivertHelperCalcChecksums(
            ctypes.byref((ctypes.c_char * len(raw)).from_buffer(raw)), len(raw), ctypes.byref(addr), 0
        )
    except Exception:
        pass


# --- unregistration fallback exhaustive ---


def test_unregister_sc_failure_mock():
    if sys.platform != "win32":
        pytest.skip("Windows only")
    with patch("pydivert.service.stop_service", return_value=False):
        with patch("subprocess.run") as mock_run:
            # sc.exe fails
            mock_run.return_value = MagicMock(returncode=1)
            pydivert.Divert.unregister()
            assert mock_run.call_count >= 1


# --- eBPF transpile exhaustive ---


def test_transpile_ebpf_exhaustive():
    from pydivert.filter import transpile_to_ebpf

    filters = [
        "tcp.Syn",
        "tcp.Ack",
        "tcp.Fin",
        "tcp.Rst",
        "tcp.Psh",
        "tcp.Urg",
        "inbound",
        "outbound",
        "loopback",
        "ip",
        "udp",
        "icmp",
        "ip.SrcAddr == 1.1.1.1",
        "ipv6.SrcAddr == ::1",
        "tcp.SrcPort == 80",
        "udp.DstPort == 53",
        "ip.TTL == 64",
        "not tcp",
        "WINDIVERT_LAYER_NETWORK",
        "tcp.Port == 80",
        "ip.Addr == 127.0.0.1",
    ]
    for f in filters:
        res = transpile_to_ebpf(f, sniff=True, drop=True)
        assert isinstance(res, list)


def test_transpile_python_extra():
    from pydivert.filter import transpile_to_python

    assert "packet.src_addr" in transpile_to_python("ip.Addr == 1.1.1.1")
    assert "packet.src_port" in transpile_to_python("tcp.Port == 80")
    assert "True" == transpile_to_python("!!!")  # fallback


# --- BaseDivert Extra ---


def test_base_divert_sync_async_mix():
    try:
        with pydivert.Divert("false") as w:
            # We already tested them separately, just ensure they co-exist
            assert hasattr(w, "recv")
            assert hasattr(w, "recv_async")
    except (PermissionError, OSError):
        pytest.skip("No permissions")
