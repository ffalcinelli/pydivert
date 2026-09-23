import errno
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import pydivert
import pydivert.base
import pydivert.ebpf
import pydivert.service
import pydivert.util
import pydivert.windivert


# util.py tests
def test_util_fromhex():
    assert pydivert.util.fromhex("aabb") == b"\xaa\xbb"
    with pytest.raises(ValueError):
        pydivert.util.fromhex("a")
    with pytest.raises(ValueError):
        pydivert.util.fromhex("xx")


def test_util_flag_property():
    class MockObj:
        def __init__(self):
            self.raw = bytearray([0])

        flag = pydivert.util.flag_property("test", 0, 0x01)

    obj = MockObj()
    assert obj.flag is False
    obj.flag = True
    assert obj.flag is True
    assert obj.raw[0] == 0x01
    obj.flag = False
    assert obj.flag is False
    assert obj.raw[0] == 0x00


def test_util_raw_property():
    class MockObj:
        def __init__(self):
            self.raw = bytearray([0, 0])

        prop = pydivert.util.raw_property(">H", 0)

    obj = MockObj()
    assert obj.prop == 0
    obj.prop = 0x1234
    assert obj.prop == 0x1234
    assert obj.raw == b"\x12\x34"


def test_util_internet_checksum():
    data = b"\x45\x00\x00\x1c\x17\xed\x40\x00\x40\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
    # Internet checksum for IP header with zero checksum field
    chk = pydivert.util.internet_checksum(data)
    assert 0 <= chk <= 0xFFFF
    assert pydivert.util.internet_checksum(b"\x01\x02\x03") == pydivert.util.internet_checksum(b"\x01\x02\x03\x00")
    assert pydivert.util.internet_checksum([1, 2, 3]) == pydivert.util.internet_checksum(b"\x01\x02\x03")


# base.py tests
class MockDivert(pydivert.base.BaseDivert):
    def _open_impl(self):
        pass

    def _close_impl(self):
        pass

    def _recv_impl(self, bufsize: int, timeout: float | None) -> pydivert.Packet:
        return MagicMock()

    def _recv_batch_impl(self, count: int, bufsize: int, timeout: float | None) -> list[pydivert.Packet]:
        return [MagicMock()]

    async def _recv_async_impl(self, bufsize: int, timeout: float | None) -> pydivert.Packet:
        return MagicMock()

    async def _recv_batch_async_impl(self, count: int, bufsize: int, timeout: float | None) -> list[pydivert.Packet]:
        return [MagicMock()]

    def _send_impl(self, packet: pydivert.Packet, recalculate_checksum: bool) -> int:
        return len(packet.raw) if hasattr(packet, "raw") else 0

    def _send_batch_impl(self, packets: list[pydivert.Packet], recalculate_checksum: bool) -> int:
        return len(packets)

    async def _send_async_impl(self, packet: pydivert.Packet, recalculate_checksum: bool) -> int:
        return len(packet.raw) if hasattr(packet, "raw") else 0

    async def _send_batch_async_impl(self, packets: list[pydivert.Packet], recalculate_checksum: bool) -> int:
        return len(packets)

    def _stats_impl(self):
        return {"test": 1}

    @staticmethod
    def register():
        pass

    @staticmethod
    def is_registered():
        return True

    @staticmethod
    def unregister():
        pass

    @staticmethod
    def check_filter(filter: str, layer: pydivert.Layer = pydivert.Layer.NETWORK) -> tuple[bool, int, str]:
        return True, 0, ""


def test_base_divert_properties():
    d = MockDivert(filter=" tcp ", priority=10, layer=pydivert.Layer.NETWORK, flags=pydivert.Flag.SNIFF)
    assert d.filter == "tcp"
    assert d.priority == 10
    assert d.layer == pydivert.Layer.NETWORK
    assert d.flags == pydivert.Flag.SNIFF
    d.filter = "udp"
    assert d.filter == "udp"
    d.priority = 20
    assert d.priority == 20
    d.layer = pydivert.Layer.NETWORK_FORWARD
    assert d.layer == pydivert.Layer.NETWORK_FORWARD
    d.flags = pydivert.Flag.DROP
    assert d.flags == pydivert.Flag.DROP


def test_base_divert_open_close():
    d = MockDivert()
    assert not d.is_open
    with d as opened:
        assert opened is d
        assert d.is_open
        with pytest.raises(RuntimeError, match="already open"):
            d.open()
    assert not d.is_open
    with pytest.raises(RuntimeError, match="not open"):
        d.close()


@pytest.mark.asyncio
async def test_base_divert_async_context():
    d = MockDivert()
    async with d as opened:
        assert opened is d
        assert d.is_open
    assert not d.is_open


def test_base_divert_recv_errors():
    d = MockDivert(flags=pydivert.Flag.SEND_ONLY)
    d.open()
    with pytest.raises(OSError, match=str(errno.EBADF)):
        d.recv()
    with pytest.raises(OSError, match=str(errno.EBADF)):
        d.recv_batch()
    d.close()


@pytest.mark.asyncio
async def test_base_divert_recv_async_errors():
    d = MockDivert(flags=pydivert.Flag.SEND_ONLY)
    d.open()
    with pytest.raises(OSError, match=str(errno.EBADF)):
        await d.recv_async()
    with pytest.raises(OSError, match=str(errno.EBADF)):
        await d.recv_batch_async()
    d.close()


def test_base_divert_send_errors():
    d = MockDivert(flags=pydivert.Flag.RECV_ONLY)
    d.open()
    with pytest.raises(OSError, match=str(errno.EACCES)):
        d.send(None)  # type: ignore
    with pytest.raises(OSError, match=str(errno.EACCES)):
        d.send_batch([])
    d.close()


@pytest.mark.asyncio
async def test_base_divert_send_async_errors():
    d = MockDivert(flags=pydivert.Flag.RECV_ONLY)
    d.open()
    with pytest.raises(OSError, match=str(errno.EACCES)):
        await d.send_async(None)  # type: ignore
    with pytest.raises(OSError, match=str(errno.EACCES)):
        await d.send_batch_async([])
    d.close()


def test_base_divert_stats():
    d = MockDivert()
    with d:
        assert d.stats() == {"test": 1}


def test_base_divert_repr():
    d = MockDivert(filter="true")
    assert "closed" in repr(d)
    with d:
        assert "open" in repr(d)


def test_base_divert_iter():
    d = MockDivert()
    d.open()
    d._recv_impl = MagicMock(side_effect=[MagicMock(), StopIteration()])  # type: ignore
    it = iter(d)
    assert next(it)
    with pytest.raises(StopIteration):
        next(it)
    d.close()


@pytest.mark.asyncio
async def test_base_divert_aiter():
    d = MockDivert()
    d.open()
    d._recv_async_impl = AsyncMock(side_effect=[MagicMock(), StopAsyncIteration()])  # type: ignore
    packets = []
    async for p in d:
        packets.append(p)
    assert len(packets) == 1
    d.close()


# jit.py tests
# service.py tests
def test_service_no_advapi():
    with patch("pydivert.service._get_advapi32", return_value=None):
        assert pydivert.service.is_registered() is False
        assert pydivert.service.stop_service() is False


def test_service_scm_fail():
    advapi32 = MagicMock()
    advapi32.OpenSCManagerW.return_value = None
    with patch("pydivert.service._get_advapi32", return_value=advapi32):
        assert pydivert.service.is_registered() is False
        assert pydivert.service.stop_service() is False


def test_service_open_fail():
    advapi32 = MagicMock()
    advapi32.OpenSCManagerW.return_value = 123
    advapi32.OpenServiceW.return_value = None
    with patch("pydivert.service._get_advapi32", return_value=advapi32):
        assert pydivert.service.is_registered() is False
        assert pydivert.service.stop_service() is False


def test_service_control_fail():
    advapi32 = MagicMock()
    advapi32.OpenSCManagerW.return_value = 123
    advapi32.OpenServiceW.return_value = 456
    advapi32.ControlService.return_value = False
    with patch("pydivert.service._get_advapi32", return_value=advapi32):
        assert pydivert.service.stop_service() is False


# filter.py tests
# ebpf.py tests
# windivert.py tests
def test_windivert_not_nt():
    with patch("os.name", "posix"):
        with pytest.raises(OSError):
            pydivert.windivert.WinDivert()


def test_windivert_unregister_sc_fallback():
    with patch("pydivert.service.stop_service", return_value=False):
        with patch("ctypes.windll", create=True) as mock_windll:
            mock_windll.kernel32.GetSystemDirectoryW.return_value = 10
            with patch("subprocess.run") as mock_run:
                pydivert.windivert.WinDivert.unregister()
                assert mock_run.call_count >= 2


def test_windivert_check_filter():
    with patch("pydivert.windivert_dll.WinDivertHelperCompileFilter", side_effect=OSError("fail")):
        res, pos, msg = pydivert.windivert.WinDivert.check_filter("true")
        assert res is False


# packet/ip.py tests
def test_ip_header_properties():
    raw = b"\x45\x00\x00\x1c\x17\xed\x40\x00\x40\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
    p = pydivert.Packet(raw)
    assert p.ipv4 is not None
    assert p.ipv4.tos == 0
    p.ipv4.tos = 1
    assert p.ipv4.tos == 1
    assert p.ipv4.ident == 0x17ED
    p.ipv4.ident = 0x1234
    assert p.ipv4.ident == 0x1234
    assert p.ipv4.ttl == 64
    p.ipv4.ttl = 128
    assert p.ipv4.ttl == 128
    assert p.ipv4.src_addr == "127.0.0.1"
    p.ipv4.src_addr = "192.168.1.1"
    assert p.ipv4.src_addr == "192.168.1.1"
    assert p.ipv4.dst_addr == "127.0.0.1"
    p.ipv4.dst_addr = "8.8.8.8"
    assert p.ipv4.dst_addr == "8.8.8.8"

    with pytest.raises(ValueError):
        p.ipv4.hdr_len = 4
    p.ipv4.hdr_len = 5
    assert p.ipv4.hdr_len == 5


# packet/__init__.py tests
def test_ipv6_extension_headers():
    raw = bytearray(b"\x60\x00\x00\x00\x00\x14\x00\x40")
    raw[6] = 0  # next_hdr=0 (Hop-by-Hop)
    raw += b"\x00" * 32  # addresses
    raw += b"\x3b\x00" + b"\x00" * 6  # Hop-by-Hop: next_hdr=59 (No Next Header), len=0 (8 bytes)
    p = pydivert.Packet(raw)
    assert p.ipv6 is not None
    proto, offset = p.protocol
    assert proto == 59
    assert offset == 48


# windivert.py overlapped tests
def test_windivert_overlapped_timeout():
    with patch("os.name", "nt"):
        with patch("pydivert.windivert.windivert_dll") as mock_dll:
            mock_dll.WinDivertOpen.return_value = 123
            mock_dll.WinDivertRecvEx.return_value = False
            mock_dll.GetLastError.return_value = 997  # ERROR_IO_PENDING
            mock_dll.ERROR_IO_PENDING = 997
            mock_dll.WaitForSingleObject.return_value = 0x00000102  # WAIT_TIMEOUT

            with patch("pydivert.windivert_dll.windll", create=True):
                d = pydivert.windivert.WinDivert()
                d._handle = 123
                d._is_open = True
                with pytest.raises(TimeoutError):
                    d.recv(timeout=0.1)


def test_windivert_overlapped_success():
    with patch("os.name", "nt"):
        with patch("pydivert.windivert.windivert_dll") as mock_dll:
            mock_dll.WinDivertOpen.return_value = 123
            mock_dll.WinDivertRecvEx.return_value = False
            mock_dll.GetLastError.return_value = 997  # ERROR_IO_PENDING
            mock_dll.ERROR_IO_PENDING = 997
            mock_dll.WaitForSingleObject.return_value = 0  # SUCCESS

            with patch("pydivert.windivert_dll.windll", create=True) as mock_windll:
                mock_windll.kernel32.GetOverlappedResult.return_value = True
                d = pydivert.windivert.WinDivert()
                d._handle = 123
                d._is_open = True
                with patch.object(d, "_parse_packet") as mock_parse:
                    d.recv(timeout=0.1)
                    assert mock_parse.called


def test_packet_no_ip():
    p = pydivert.Packet(b"\x00\x00\x00\x00")
    assert p.ipv4 is None
    assert p.ipv6 is None
    assert p.tcp is None
    assert p.udp is None
    assert p.icmp is None
    proto, start = p.protocol
    assert proto is None
    assert start is None


def test_packet_truncated_ipv4():
    p = pydivert.Packet(b"\x45")
    assert p.ipv4 is None
    p2 = pydivert.Packet(b"\x45\x00\x00")
    assert p2.ipv4 is None


def test_packet_truncated_ipv6():
    p = pydivert.Packet(b"\x60")
    assert p.ipv6 is None
    p2 = pydivert.Packet(b"\x60\x00\x00")
    assert p2.ipv6 is None


def test_packet_truncated_tcp():
    raw = b"\x45\x00\x00\x28\x00\x00\x00\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
    p = pydivert.Packet(raw)
    assert p.ipv4 is not None
    assert p.tcp is not None


def test_packet_none_headers():
    raw = b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\xfe\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
    p = pydivert.Packet(raw)
    assert p.ipv4 is not None
    assert p.ipv4.protocol == 254
    assert p.tcp is None
    assert p.udp is None
    assert p.icmp is None


def test_packet_property_setters():
    p = pydivert.Packet(b"\x45" + b"\x00" * 19)
    p.interface = 5
    assert p.interface == (5, 0)
    p.interface = (1, 2)
    assert p.interface == (1, 2)
    p.direction = pydivert.Direction.OUTBOUND
    assert p.direction == pydivert.Direction.OUTBOUND
    p.timestamp = 12345
    assert p.timestamp == 12345
    p.loopback = True
    assert p.loopback is True
    p.is_loopback = False
    assert p.is_loopback is False


def test_windivert_check_filter_error():
    with patch("pydivert.windivert_dll.WinDivertHelperCompileFilter", return_value=False):
        with patch("pydivert.windivert_dll.GetLastError", return_value=123):
            res, pos, msg = pydivert.windivert.WinDivert.check_filter("invalid")
            assert res is False
            assert pos == 0


def test_windivert_ex_methods():
    from pydivert.windivert_dll.structs import WinDivertAddress

    with patch("os.name", "nt"):
        with patch("pydivert.windivert.windivert_dll") as mock_dll:
            mock_dll.WinDivertOpen.return_value = 123
            d = pydivert.windivert.WinDivert()
            d._handle = 123
            d._is_open = True

            mock_dll.WinDivertRecvEx.return_value = True
            with patch.object(d, "_parse_packet"):
                d.recv_ex()
                assert mock_dll.WinDivertRecvEx.called

            mock_dll.WinDivertSendEx.return_value = True
            p = MagicMock(spec=pydivert.Packet)
            p.raw = bytearray(b"data")
            p.wd_addr = WinDivertAddress()
            p.recalculate_checksums = MagicMock()
            d.send_ex(p)
            assert mock_dll.WinDivertSendEx.called


def test_ipv6_header_properties():
    raw = bytearray(b"\x60\x00\x00\x00\x00\x00\x3b\x40")
    raw += b"\x00" * 16  # src
    raw += b"\x00" * 16  # dst
    p = pydivert.Packet(raw)
    assert p.ipv6 is not None
    assert p.ipv6.traffic_class == 0
    p.ipv6.traffic_class = 1
    assert p.ipv6.traffic_class == 1
    assert p.ipv6.flow_label == 0
    p.ipv6.flow_label = 0x12345
    assert p.ipv6.flow_label == 0x12345
    assert p.ipv6.payload_len == 0
    p.ipv6.payload_len = 100
    assert p.ipv6.payload_len == 100
    assert p.ipv6.next_hdr == 59
    p.ipv6.next_hdr = 6
    assert p.ipv6.next_hdr == 6
    assert p.ipv6.hop_limit == 64
    p.ipv6.hop_limit = 128
    assert p.ipv6.hop_limit == 128
    assert p.ipv6.src_addr == "::"
    p.ipv6.src_addr = "2001:db8::1"
    assert p.ipv6.src_addr == "2001:db8::1"
    assert p.ipv6.dst_addr == "::"
    p.ipv6.dst_addr = "fe80::1"
    assert p.ipv6.dst_addr == "fe80::1"


def test_packet_additional_properties():
    p = pydivert.Packet(b"\x45" + b"\x00" * 19)
    assert p.flow is None
    assert p.socket is None
    assert p.reflect is None

    raw_v4 = b"\x45\x00\x00\x1c\x00\x00\x00\x00\x40\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
    raw_v4 += b"\x08\x00\x00\x00\x00\x00\x00\x00"  # Echo request
    p4 = pydivert.Packet(raw_v4)
    assert p4.icmpv4 is not None
    assert p4.icmpv6 is None
    assert p4.icmp is not None

    raw_v6 = bytearray(b"\x60\x00\x00\x00\x00\x08\x3a\x40")
    raw_v6 += b"\x00" * 32  # addresses
    raw_v6 += b"\x80\x00\x00\x00\x00\x00\x00\x00"  # Echo request
    p6 = pydivert.Packet(raw_v6)
    assert p6.icmpv6 is not None
    assert p6.icmpv4 is None
    assert p6.icmp is not None


def test_packet_repr_unknown_proto():
    p = pydivert.Packet(b"\x45" + b"\x00" * 19)
    p.__dict__["protocol"] = (255, 20)
    r = repr(p)
    assert "255" in r


def test_packet_icmp_none():
    p = pydivert.Packet(b"\x45" + b"\x00" * 19)
    assert p.icmpv4 is None
    assert p.icmpv6 is None


def test_base_divert_error_messages():
    d = MockDivert()
    with pytest.raises(RuntimeError, match="already open"):
        d._is_open = True
        d.open()
    d._is_open = False
    with pytest.raises(RuntimeError, match="not open"):
        d.close()
    with pytest.raises(RuntimeError, match="not open"):
        d.stats()


def test_ipv4_full_properties():
    raw = bytearray(b"\x45\x00\x00\x14\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    p = pydivert.Packet(raw)
    v4 = p.ipv4
    assert v4 is not None
    assert v4.hdr_len == 5

    assert v4.hdr_len == 5
    v4.hdr_len = 6
    assert v4.hdr_len == 6
    assert v4.tos == 0
    v4.tos = 0x10
    assert v4.tos == 0x10
    assert v4.diff_serv == 4
    v4.diff_serv = 8
    assert v4.diff_serv == 8
    assert v4.ecn == 0
    v4.ecn = 1
    assert v4.ecn == 1
    assert v4.dscp == 8
    v4.dscp = 12
    assert v4.dscp == 12
    assert v4.packet_len == 20
    assert v4.ident == 0
    v4.ident = 0xABCD
    assert v4.ident == 0xABCD
    assert v4.flags == 2  # DF
    v4.flags = 0
    assert v4.flags == 0
    assert v4.frag_offset == 0
    v4.frag_offset = 100
    assert v4.frag_offset == 100
    assert v4.ttl == 64
    v4.ttl = 128
    assert v4.ttl == 128
    assert v4.protocol == 6
    v4.protocol = 17
    assert v4.protocol == 17
    assert v4.cksum == 0
    v4.cksum = 0x1234
    assert v4.cksum == 0x1234
    assert v4.src_addr == "127.0.0.1"
    v4.src_addr = "10.0.0.1"
    assert v4.src_addr == "10.0.0.1"
    assert v4.dst_addr == "127.0.0.1"
    v4.dst_addr = "10.0.0.2"
    assert v4.dst_addr == "10.0.0.2"


def test_ipv6_full_properties():
    raw = bytearray(b"\x60\x00\x00\x00\x00\x00\x3b\x40")
    raw += b"\x00" * 32
    p = pydivert.Packet(raw)
    v6 = p.ipv6
    assert v6 is not None
    assert v6.traffic_class == 0
    assert v6.traffic_class == 0
    v6.traffic_class = 0xAB
    assert v6.traffic_class == 0xAB
    assert v6.flow_label == 0
    v6.flow_label = 0x12345
    assert v6.flow_label == 0x12345
    assert v6.payload_len == 0
    v6.payload_len = 100
    assert v6.payload_len == 100
    assert v6.next_hdr == 59
    v6.next_hdr = 17
    assert v6.next_hdr == 17
    assert v6.hop_limit == 64
    v6.hop_limit = 255
    assert v6.hop_limit == 255
    assert v6.src_addr == "::"
    v6.src_addr = "2001:db8::1"
    assert v6.src_addr == "2001:db8::1"
    assert v6.dst_addr == "::"
    v6.dst_addr = "2001:db8::2"
    assert v6.dst_addr == "2001:db8::2"


def test_tcp_full_properties():
    raw = bytearray(b"\x45\x00\x00\x28\x00\x00\x00\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    raw += b"\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x00\x00\x00\x00\x00\x00"
    p = pydivert.Packet(raw)
    tcp = p.tcp
    assert tcp is not None
    assert tcp.src_port == 80
    assert tcp.src_port == 80
    tcp.src_port = 1234
    assert tcp.src_port == 1234
    assert tcp.dst_port == 80
    tcp.dst_port = 5678
    assert tcp.dst_port == 5678
    assert tcp.seq_num == 0
    tcp.seq_num = 0x12345678
    assert tcp.seq_num == 0x12345678
    assert tcp.ack_num == 0
    tcp.ack_num = 0x87654321
    assert tcp.ack_num == 0x87654321
    assert tcp.header_len == 20
    tcp.data_offset = 8
    assert tcp.header_len == 32
    assert tcp.reserved == 0
    tcp.reserved = 7
    assert tcp.reserved == 7
    assert tcp.control_bits == 2  # SYN
    tcp.control_bits = 0x12  # SYN+ACK
    assert tcp.control_bits == 0x12
    assert tcp.syn is True
    tcp.syn = False
    assert tcp.syn is False
    assert tcp.window == 0
    tcp.window = 65535
    assert tcp.window == 65535
    assert tcp.cksum == 0
    tcp.cksum = 0xABCD
    assert tcp.cksum == 0xABCD
    assert tcp.urg_ptr == 0
    tcp.urg_ptr = 100
    assert tcp.urg_ptr == 100


def test_udp_full_properties():
    raw = bytearray(b"\x45\x00\x00\x1c\x00\x00\x00\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    raw += b"\x00\x35\x00\x35\x00\x08\x00\x00"
    p = pydivert.Packet(raw)
    udp = p.udp
    assert udp is not None
    assert udp.src_port == 53
    assert udp.src_port == 53
    udp.src_port = 1234
    assert udp.src_port == 1234
    assert udp.dst_port == 53
    udp.dst_port = 5678
    assert udp.dst_port == 5678
    assert udp.payload_len == 0
    assert udp.cksum == 0
    udp.cksum = 0x1234
    assert udp.cksum == 0x1234


def test_icmp_full_properties():
    raw = bytearray(b"\x45\x00\x00\x1c\x00\x00\x00\x00\x40\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    raw += b"\x08\x00\x00\x00\x00\x00\x00\x00"
    p = pydivert.Packet(raw)
    icmp = p.icmp
    assert icmp is not None
    assert icmp.type == 8
    assert icmp.type == 8
    icmp.type = 0
    assert icmp.type == 0
    assert icmp.code == 0
    icmp.code = 1
    assert icmp.code == 1
    assert icmp.cksum == 0
    icmp.cksum = 0x1234
    assert icmp.cksum == 0x1234


def test_packet_all_properties_hit():
    raw = bytearray(b"\x45\x00\x00\x28\x00\x00\x00\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    raw += b"\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x00\x00\x00\x00\x00\x00"
    p = pydivert.Packet(raw)

    _ = p.ipv4
    _ = p.ipv6
    _ = p.tcp
    _ = p.udp
    _ = p.icmp
    _ = p.icmpv4
    _ = p.icmpv6
    _ = p.protocol
    _ = p.src_addr
    _ = p.dst_addr
    _ = p.src_port
    _ = p.dst_port
    _ = p.payload
    _ = p.interface
    _ = p.direction
    _ = p.timestamp
    _ = p.is_loopback
    _ = p.is_impostor
    _ = p.is_sniffed
    _ = p.ip_checksum
    _ = p.tcp_checksum
    _ = p.udp_checksum
    _ = p.icmp_checksum

    raw6 = bytearray(b"\x60\x00\x00\x00\x00\x00\x3b\x40")
    raw6 += b"\x00" * 32
    p6 = pydivert.Packet(raw6)
    _ = p6.ipv6
    _ = p6.protocol
    _ = p6.src_addr
    _ = p6.dst_addr


def test_windivert_params():
    with patch("os.name", "nt"):
        with patch("pydivert.windivert.windivert_dll") as mock_dll:
            mock_dll.WinDivertOpen.return_value = 123
            d = pydivert.windivert.WinDivert()
            d._handle = 123
            d._is_open = True

            mock_dll.WinDivertGetParam.return_value = True
            d.get_param(pydivert.Param.QUEUE_SIZE)
            assert mock_dll.WinDivertGetParam.called

            mock_dll.WinDivertSetParam.return_value = True
            d.set_param(pydivert.Param.QUEUE_SIZE, 200)
            assert mock_dll.WinDivertSetParam.called


def test_packet_shortcuts_hit():
    raw = bytearray(b"\x45\x00\x00\x1c\x00\x00\x00\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    raw += b"\x00\x35\x00\x35\x00\x08\x00\x00"
    p = pydivert.Packet(raw)

    assert p.src_addr == "127.0.0.1"
    p.src_addr = "10.0.0.1"
    assert p.src_addr == "10.0.0.1"

    assert p.dst_addr == "127.0.0.1"
    p.dst_addr = "10.0.0.2"
    assert p.dst_addr == "10.0.0.2"

    assert p.src_port == 53
    p.src_port = 1234
    assert p.src_port == 1234

    assert p.dst_port == 53
    p.dst_port = 5678
    assert p.dst_port == 5678

    p_no_udp = pydivert.Packet(b"\x45" + b"\x00" * 19)
    assert p_no_udp.src_port is None
    assert p_no_udp.dst_port is None

    p_no_ip = pydivert.Packet(b"\x00" * 4)
    assert p_no_ip.src_addr is None
    assert p_no_ip.dst_addr is None


@pytest.mark.asyncio
async def test_windivert_recv_async_mock():
    with patch("os.name", "nt"):
        with patch("pydivert.windivert.windivert_dll") as mock_dll:
            mock_dll.WinDivertOpen.return_value = 123
            mock_dll.WinDivertRecvEx.return_value = True
            mock_dll.ERROR_IO_PENDING = 997
            mock_dll.CreateEventW.return_value = 456

            from pydivert.windivert import WinDivert

            d = WinDivert()
            d._handle = 123
            d._is_open = True

            with patch.object(d, "_parse_packet") as mock_parse:
                mock_parse.return_value = MagicMock()
                res = await d.recv_async()
                assert res is not None


def test_divert_facade_hit():
    d = pydivert.Divert(filter="false")
    assert d.filter == "false"
    d.filter = "true"
    # Because of __setattr__ bypass, d.filter remains false but impl is updated
    assert d._impl.filter == "true"

    assert pydivert.Divert.is_registered() is True

    with patch("pydivert.core.sys.platform", "darwin"):
        with pytest.raises(NotImplementedError):
            pydivert.Divert._get_implementation_class()


def test_windivert_batch_logic():
    with patch("os.name", "nt"):
        with patch("pydivert.windivert.windivert_dll") as mock_dll:
            mock_dll.WinDivertOpen.return_value = 123
            d = pydivert.windivert.WinDivert()
            d._handle = 123
            d._is_open = True

            mock_dll.WinDivertRecv.return_value = True
            with patch.object(d, "_parse_packet") as mock_parse:
                mock_parse.return_value = MagicMock()
                # batch loop calls _recv_impl which we can mock
                with patch.object(d, "_recv_impl") as mock_recv:
                    mock_recv.return_value = MagicMock()
                    assert len(d.recv_batch(count=1)) == 1

            mock_dll.WinDivertSend.return_value = True

            def send_side_effect(*args):
                return True

            mock_dll.WinDivertSend.side_effect = send_side_effect

            p = MagicMock(spec=pydivert.Packet)
            p.direction = None
            p.wd_addr = MagicMock()
            p.raw = bytearray(b"data")
            with patch.object(d, "_send_impl", return_value=4):
                assert d._send_batch_impl([p], False) == 1


@pytest.mark.asyncio
async def test_windivert_batch_async_logic():
    with patch("os.name", "nt"):
        with patch("pydivert.windivert.windivert_dll") as mock_dll:
            mock_dll.WinDivertOpen.return_value = 123
            d = pydivert.windivert.WinDivert()
            d._handle = 123
            d._is_open = True

            with patch.object(d, "_recv_async_impl") as mock_recv:
                mock_recv.return_value = MagicMock()
                assert len(await d.recv_batch_async(count=1)) == 1

            mock_dll.WinDivertSend.return_value = True

            def send_side_effect(*args):
                return True

            mock_dll.WinDivertSend.side_effect = send_side_effect

            p = MagicMock(spec=pydivert.Packet)
            p.direction = None
            p.wd_addr = MagicMock()
            p.raw = bytearray(b"data")
            with patch.object(d, "_send_impl", return_value=4):
                assert await d._send_batch_async_impl([p], False) == 1


def test_packet_is_loopback_setter():
    p = pydivert.Packet(b"\x45" + b"\x00" * 19)
    p.is_loopback = True
    assert p.is_loopback is True
    assert p._wd_addr.Loopback == 1
    p.is_loopback = False
    assert p.is_loopback is False
    assert p._wd_addr.Loopback == 0


@pytest.mark.asyncio
async def test_windivert_send_async_impl():
    with patch("os.name", "nt"):
        with patch("pydivert.windivert.windivert_dll") as mock_dll:
            mock_dll.WinDivertOpen.return_value = 123
            d = pydivert.windivert.WinDivert()
            d._handle = 123
            d._is_open = True

            p = MagicMock(spec=pydivert.Packet)
            p.raw = bytearray(b"data")
            from pydivert.windivert_dll.structs import WinDivertAddress

            p.wd_addr = WinDivertAddress()

            mock_dll.WinDivertSendEx.return_value = False
            mock_dll.GetLastError.return_value = 997  # ERROR_IO_PENDING
            mock_dll.ERROR_IO_PENDING = 997
            mock_dll.WaitForSingleObject.return_value = 0  # SUCCESS

            with patch("pydivert.windivert_dll.windll", create=True) as mock_windll:
                mock_windll.kernel32.GetOverlappedResult.return_value = True

                res = await d._send_async_impl(p, False)
                # It should return 0 because we didn't mock send_len value
                assert res == 0


@pytest.mark.asyncio
async def test_windivert_send_async_impl_error():
    with patch("os.name", "nt"):
        with patch("pydivert.windivert.windivert_dll") as mock_dll:
            mock_dll.WinDivertOpen.return_value = 123
            d = pydivert.windivert.WinDivert()
            d._handle = 123
            d._is_open = True

            p = MagicMock(spec=pydivert.Packet)
            p.raw = bytearray(b"data")
            from pydivert.windivert_dll.structs import WinDivertAddress

            p.wd_addr = WinDivertAddress()

            mock_dll.WinDivertSendEx.return_value = False
            mock_dll.GetLastError.return_value = 123  # Generic error
            mock_dll.ERROR_IO_PENDING = 997
            mock_dll.WinError = OSError

            with pytest.raises(OSError):
                await d._send_async_impl(p, False)


def test_windivert_close_errors():
    with patch("os.name", "nt"):
        with patch("pydivert.windivert.windivert_dll") as mock_dll:
            d = pydivert.windivert.WinDivert()
            d._handle = 123
            d._is_open = True

            d._close_impl()
            assert mock_dll.WinDivertClose.called


def test_packet_address_props_more():
    with patch("os.name", "nt"):
        raw = bytearray(b"\x45\x00\x00\x14\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
        p = pydivert.Packet(raw)
        p.interface = (1, 2)
        assert p.interface == (1, 2)
        assert p._wd_addr.Network.IfIdx == 1
        assert p._wd_addr.Network.SubIfIdx == 2

        p.direction = pydivert.Direction.OUTBOUND
        assert p.direction == pydivert.Direction.OUTBOUND

        p.timestamp = 100
        assert p.timestamp == 100
        assert p._wd_addr.Timestamp == 100

        p.is_impostor = True
        assert p.is_impostor is True
        assert p._wd_addr.Impostor == 1
        p.is_impostor = False
        assert p.is_impostor is False
        assert p._wd_addr.Impostor == 0

        p.is_sniffed = True
        assert p.is_sniffed is True
        assert p._wd_addr.Sniffed == 1
        p.is_sniffed = False
        assert p.is_sniffed is False
        assert p._wd_addr.Sniffed == 0

        p.ip_checksum = True
        assert p.ip_checksum is True
        assert p._wd_addr.IPChecksum == 1
        p.ip_checksum = False
        assert p.ip_checksum is False
        assert p._wd_addr.IPChecksum == 0

        p.tcp_checksum = True
        assert p.tcp_checksum is True
        assert p._wd_addr.TCPChecksum == 1
        p.tcp_checksum = False
        assert p.tcp_checksum is False
        assert p._wd_addr.TCPChecksum == 0

        p.udp_checksum = True
        assert p.udp_checksum is True
        assert p._wd_addr.UDPChecksum == 1
        p.udp_checksum = False
        assert p.udp_checksum is False
        assert p._wd_addr.UDPChecksum == 0


def test_windivert_register():
    with patch("os.name", "nt"):
        with patch("pydivert.windivert.windivert_dll") as mock_dll:
            mock_dll.WinDivertOpen.return_value = 123
            from pydivert.windivert import WinDivert

            WinDivert.register()
            assert mock_dll.WinDivertOpen.called


def test_windivert_is_registered():
    with patch("os.name", "nt"):
        from pydivert.windivert import WinDivert

        with patch("pydivert.service.is_registered", return_value=True):
            assert WinDivert.is_registered() is True


def test_packet_with_wd_addr():
    from pydivert.windivert_dll.structs import WinDivertAddress

    raw = bytearray(b"\x45" + b"\x00" * 19)
    addr = WinDivertAddress()
    addr.u.Network.IfIdx = 1
    addr.u.Network.SubIfIdx = 2
    addr.Outbound = 1
    addr.Timestamp = 1234
    addr.Loopback = 1
    addr.Impostor = 1
    addr.Sniffed = 1
    addr.IPChecksum = 1
    addr.TCPChecksum = 1
    addr.UDPChecksum = 1
    p = pydivert.Packet(raw, wd_addr=addr)
    assert p.interface == (1, 2)
    assert p.direction == pydivert.Direction.OUTBOUND
    assert p.timestamp == 1234
    assert p.is_loopback is True
    assert p.is_impostor is True
    assert p.is_sniffed is True

    p2 = pydivert.Packet(memoryview(raw))
    assert p2.raw == raw


def test_packet_recalculate_checksums_no_headers():
    p = pydivert.Packet(b"\x00" * 4)
    assert p.recalculate_checksums() == 0
