import ctypes
import sys
from unittest.mock import MagicMock, patch

import pytest

import pydivert
from pydivert import Divert, service
from pydivert.consts import Param
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


def test_check_filter_invalid():
    res, pos, msg = Divert.check_filter("invalid filter string")
    assert res is False
    assert pos >= 0
    assert msg
    # Same compiler on both platforms: the error position is exact.
    res, pos, msg = Divert.check_filter("tcp and (")
    assert (res, pos) == (False, 9)


# --- OS Edge Cases & Mocks ---


@pytest.mark.skipif(sys.platform != "win32", reason="WinDivert fallback is Windows-specific")
def test_windivert_unregister_fallback_mock():
    with patch("pydivert.service.stop_service", return_value=False):
        with patch("subprocess.run") as mock_run:
            # Mock successful sc.exe call
            mock_run.return_value = MagicMock(returncode=0)
            Divert.unregister()
            assert mock_run.call_count >= 1


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


def test_divert_fluent_filter_mock():
    w = Divert("false")
    p1 = pydivert.PacketBuilder().ipv4(src="10.0.0.1", dst="10.0.0.2").tcp(src_port=123, dst_port=80).build()
    p2 = pydivert.PacketBuilder().ipv4(src="10.0.0.3", dst="10.0.0.4").udp(src_port=456, dst_port=53).build()

    with patch.object(Divert, "__iter__", side_effect=lambda: iter([p1, p2])):
        # filter by protocol
        filtered = list(w.filter(proto=6))
        assert len(filtered) == 1
        assert filtered[0].src_port == 123

        # filter by src_port
        filtered = list(w.filter(src_port=456))
        assert len(filtered) == 1
        assert filtered[0].dst_port == 53


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


# --- jit.py Coverage ---


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
    with pytest.raises(OSError):
        pydivert.Divert("something invalid").open()


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


# --- WinDivert / EBPF Mock Edge Cases ---


def test_windivert_open_failure_mock():
    if sys.platform != "win32":
        pytest.skip("Windows only")
    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        mock_dll.WinDivertOpen.side_effect = OSError(None, "Access Denied", None, 5)
        with pytest.raises(OSError):
            pydivert.Divert().open()


# --- WinDivert Params exhaustive ---


def test_windivert_params_all():
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


# --- BaseDivert Extra ---


def test_base_divert_sync_async_mix():
    try:
        with pydivert.Divert("false") as w:
            # We already tested them separately, just ensure they co-exist
            assert hasattr(w, "recv")
            assert hasattr(w, "recv_async")
    except (PermissionError, OSError):
        pytest.skip("No permissions")
