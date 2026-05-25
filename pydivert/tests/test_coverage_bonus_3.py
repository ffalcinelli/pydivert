# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys

import pytest

import pydivert
from pydivert.consts import Direction, Flag, Layer
from pydivert.packet import Packet
from pydivert.windivert_dll.structs import WinDivertAddress


def test_packet_metadata_getset():
    p = Packet(b"E" + b"\x00" * 19)  # dummy IP

    # Test interface
    p.interface = 5
    assert p.interface == (5, 0)
    p.interface = (10, 1)
    assert p.interface == (10, 1)

    # Test direction
    p.direction = Direction.INBOUND
    assert p.direction == Direction.INBOUND
    assert p.is_inbound
    assert not p.is_outbound
    p.is_outbound = True
    assert p.direction == Direction.OUTBOUND
    p.is_inbound = True
    assert p.direction == Direction.INBOUND

    # Test timestamp
    p.timestamp = 123456
    assert p.timestamp == 123456

    # Test loopback
    p.is_loopback = True
    assert p.is_loopback
    assert p.loopback
    p.loopback = False
    assert not p.is_loopback

    # Test impostor
    p.is_impostor = True
    assert p.is_impostor
    assert p.impostor
    p.impostor = False
    assert not p.is_impostor

    # Test sniffed
    p.is_sniffed = True
    assert p.is_sniffed
    assert p.sniffed
    p.sniffed = False
    assert not p.is_sniffed

    # Test event
    p.event = 7
    assert p.event == 7

    # Test layer and union syncing
    p.layer = Layer.FLOW
    flow_data = WinDivertAddress._Union._Flow()
    flow_data.ProcessId = 1234
    p.flow = flow_data
    assert p.flow.ProcessId == 1234

    p.layer = Layer.SOCKET
    sock_data = WinDivertAddress._Union._Socket()
    sock_data.ProcessId = 5678
    p.socket = sock_data
    assert p.socket.ProcessId == 5678

    p.layer = Layer.REFLECT
    refl_data = WinDivertAddress._Union._Reflect()
    refl_data.ProcessId = 9999
    p.reflect = refl_data
    assert p.reflect.ProcessId == 9999

    # Coverage for wd_addr property
    assert p.wd_addr is not None


def test_packet_ipv6_ext_headers():
    # IPv6 header (40 bytes) + Hop-by-Hop (8 bytes) + TCP header
    raw = bytearray(b"\x60\x00\x00\x00\x00\x14\x00\x40")
    raw += b"\x00" * 32  # addresses
    # Hop-by-Hop: NextHeader=6 (TCP), HdrExtLen=0 (8 bytes total)
    raw += b"\x06\x00\x00\x00\x00\x00\x00\x00"
    raw += b"\x00" * 20  # dummy TCP

    p = Packet(raw)
    proto, offset = p.protocol
    assert proto == 6
    assert offset == 48

    # Test AH header (51) - use a fresh raw to avoid BufferError
    raw_ah = bytearray(b"\x60\x00\x00\x00\x00\x14\x33\x40")  # 0x33 = 51
    raw_ah += b"\x00" * 32
    # AH header: NextHeader=6 (TCP), PayloadLen=2 ( (2+2)*4 = 16 bytes)
    raw_ah += b"\x06\x02\x00\x00\x00\x00\x00\x00"
    raw_ah += b"\x00" * 8  # AH padding
    raw_ah += b"\x00" * 20  # TCP

    p2 = Packet(raw_ah)
    proto2, offset2 = p2.protocol
    assert proto2 == 6
    assert offset2 == 56


def test_packet_matches_unsupported():
    if sys.platform != "win32":
        p = Packet(b"E" + b"\x00" * 19)
        with pytest.raises(NotImplementedError, match="only supported on Windows"):
            p.matches("ip")


def test_filter_edge_cases():
    from pydivert.filter import normalize_filter, transpile_to_ebpf, transpile_to_python, transpile_to_rules

    # Ternary in LegacyTransformer
    assert normalize_filter("ip ? tcp : udp") == "(ip ? tcp : udp)"

    # not_expr in PythonEvalTransformer
    assert transpile_to_python("!ip") == "(not packet.ip)"

    # Unknown field in PythonEvalTransformer fallback
    assert "packet.unknown_field" in transpile_to_python("unknown_field == 1")

    # Logic OR/AND in PythonEvalTransformer
    assert "and" in transpile_to_python("ip and tcp")
    assert "or" in transpile_to_python("ip or tcp")

    # transpile_to_rules unusual cases
    assert transpile_to_rules("loopback == true") == [{}]
    assert transpile_to_rules("!ip and tcp") == [{"proto": "tcp"}]
    assert transpile_to_rules("(ip or tcp) == true") == [{}]

    # Trigger _handle_port_comparison branches
    assert transpile_to_rules("tcp.port == 80") is not None
    assert transpile_to_rules("udp.port == 53") is not None
    assert transpile_to_rules("tcp.srcport == 1234") == [{"proto": "tcp", "sport": "1234"}]

    # Trigger _handle_addr_comparison branches
    assert transpile_to_rules("ip.src == 1.1.1.1") == [{"srcaddr": "1.1.1.1"}]
    assert transpile_to_rules("ip.dst == 2.2.2.2") == [{"dstaddr": "2.2.2.2"}]
    assert transpile_to_rules("ip.addr == 3.3.3.3") is not None
    assert transpile_to_rules("ipv6.src == ::1") == [{"srcaddr": "::1", "loopback": True}]

    # Trigger ip.ttl branch
    assert transpile_to_rules("ip.ttl == 64") == [{"ttl": "64"}]

    # Trigger transpile_to_ebpf branches
    assert transpile_to_ebpf("ip and tcp and udp and icmp", sniff=True, drop=True) is not None
    assert transpile_to_ebpf("inbound and outbound and loopback") is not None
    assert transpile_to_ebpf("tcp.syn and tcp.ack and tcp.fin and tcp.rst and tcp.psh and tcp.urg") is not None
    assert transpile_to_ebpf("ip.ttl == 128") is not None
    assert transpile_to_ebpf("false") is not None


@pytest.mark.asyncio
async def test_base_async_iterator_simple():
    try:
        with pydivert.Divert("false") as d:
            it = d.__aiter__()
            assert it is d
    except PermissionError:
        pytest.skip("Root privileges required")
    except Exception as e:
        if "WinDivert" in str(e):
            pytest.skip("WinDivert not available")
        raise


@pytest.mark.asyncio
async def test_base_async_context_manager_error():
    try:
        d = pydivert.Divert("false")
        try:
            async with d:
                assert d.is_open
                raise ValueError("test error")
        except ValueError:
            pass
        assert not d.is_open
    except (PermissionError, OSError):
        pytest.skip("Insufficient privileges or backend missing")


def test_divert_send_only_recv_only_errors():
    try:
        with pydivert.Divert("false", flags=Flag.SEND_ONLY) as w:
            with pytest.raises(OSError, match="Handle is send-only"):
                w.recv()
            with pytest.raises(OSError, match="Handle is send-only"):
                w.recv_batch()

        with pydivert.Divert("false", flags=Flag.RECV_ONLY) as w:
            p = Packet(b"E" + b"\x00" * 19)
            p.dst_addr = "127.0.0.1"
            with pytest.raises(OSError, match="Handle is recv-only"):
                w.send(p)
    except (PermissionError, OSError):
        pytest.skip("Insufficient privileges or backend missing")


@pytest.mark.asyncio
async def test_divert_async_send_only_recv_only_errors():
    try:
        with pydivert.Divert("false", flags=Flag.SEND_ONLY) as w:
            with pytest.raises(OSError, match="Handle is send-only"):
                await w.recv_async(timeout=0.1)
            with pytest.raises(OSError, match="Handle is send-only"):
                await w.recv_batch_async(count=1, timeout=0.1)

        with pydivert.Divert("false", flags=Flag.RECV_ONLY) as w:
            p = Packet(b"E" + b"\x00" * 19)
            p.dst_addr = "127.0.0.1"
            with pytest.raises(OSError, match="Handle is recv-only"):
                await w.send_async(p)
    except (PermissionError, OSError):
        pytest.skip("Insufficient privileges or backend missing")


def test_transpile_to_python_failure():
    from pydivert.filter import transpile_to_python

    assert transpile_to_python("!!! invalid !!!") == "True"


def test_base_stats_not_open():
    d = pydivert.Divert("false")
    with pytest.raises(RuntimeError, match="not open"):
        d.stats()


def test_base_send_not_open():
    d = pydivert.Divert("false")
    p = Packet(b"E" + b"\x00" * 19)
    with pytest.raises(RuntimeError, match="not open"):
        d.send(p)


@pytest.mark.asyncio
async def test_base_send_async_not_open():
    d = pydivert.Divert("false")
    p = Packet(b"E" + b"\x00" * 19)
    with pytest.raises(RuntimeError, match="not open"):
        await d.send_async(p)


def test_ebpf_stats():
    try:
        with pydivert.Divert("false") as w:
            s = w.stats()
            assert isinstance(s, dict)
    except (PermissionError, OSError):
        pytest.skip("Insufficient privileges or backend missing")


def test_ebpf_batching():
    if sys.platform == "win32":
        pytest.skip("WinDivert returns empty list on batch timeout instead of raising TimeoutError")
    try:
        with pydivert.Divert("false") as w:
            # recv_batch with timeout should raise TimeoutError on Linux
            with pytest.raises(TimeoutError):
                w.recv_batch(count=2, timeout=0.1)
    except (PermissionError, OSError):
        pytest.skip("Insufficient privileges or backend missing")


@pytest.mark.asyncio
async def test_ebpf_batching_async():
    if sys.platform == "win32":
        pytest.skip("WinDivert returns empty list on batch timeout instead of raising TimeoutError")
    try:
        with pydivert.Divert("false") as w:
            with pytest.raises(TimeoutError):
                await w.recv_batch_async(count=2, timeout=0.1)
    except (PermissionError, OSError):
        pytest.skip("Insufficient privileges or backend missing")


def test_divert_check_filter_invalid():
    res, code, msg = pydivert.Divert.check_filter("!!! invalid !!!")
    assert not res
    if sys.platform != "win32":
        assert code == -1
    else:
        # On Windows it returns the position of the error
        assert code >= 0
