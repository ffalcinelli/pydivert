# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import ctypes
import errno
import sys
from unittest.mock import MagicMock, patch

import pytest

import pydivert
import pydivert.ebpf

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="eBPF only supported on Linux")


def test_ebpf_unsupported_layer():
    """Test that unsupported layers raise NotImplementedError."""
    with pytest.raises(NotImplementedError):
        pydivert.EBPFDivert(layer=pydivert.Layer.REFLECT)


def test_ebpf_send_only_recv_fails():
    """Test that recv() fails on a send-only handle."""
    with pydivert.Divert(flags=pydivert.Flag.SEND_ONLY, interfaces=["lo"]) as w:
        with pytest.raises(OSError) as excinfo:
            w.recv()
        assert excinfo.value.errno == errno.EBADF


def test_ebpf_recv_only_send_fails():
    """Test that send() fails on a receive-only handle."""
    with pydivert.Divert(flags=pydivert.Flag.RECV_ONLY, interfaces=["lo"]) as w:
        with pytest.raises(OSError) as excinfo:
            w.send(pydivert.Packet(b"raw"))
        assert excinfo.value.errno == errno.EACCES


@pytest.mark.asyncio
async def test_ebpf_recv_async_send_only():
    """Test that recv_async() fails on a send-only handle."""
    with pydivert.Divert(flags=pydivert.Flag.SEND_ONLY, interfaces=["lo"]) as w:
        with pytest.raises(OSError):
            await w.recv_async()


@pytest.mark.asyncio
async def test_ebpf_send_async_recv_only():
    """Test that send_async() fails on a receive-only handle."""
    with pydivert.Divert(flags=pydivert.Flag.RECV_ONLY, interfaces=["lo"]) as w:
        with pytest.raises(OSError):
            await w.send_async(pydivert.Packet(b"raw"))


def test_ebpf_ring_callback_heuristics():
    """Test L2 offset heuristics in _ring_callback."""
    # We need to manually call _ring_callback on an EBPFDivert instance
    with pydivert.Divert("false", flags=pydivert.Flag.SNIFF, interfaces=["lo"]) as w:
        ebpf_divert = w._impl

        class FakeHeader:
            def __init__(self, pkt_len, ifindex, direction, l2_len):
                self.pkt_len = pkt_len
                self.ifindex = ifindex
                self.direction = direction
                self.l2_len = l2_len

        class FakeBuf:
            def __init__(self, header, data):
                self.header = header
                self.data = data

            @classmethod
            def from_address(cls, addr):
                return cls.stored_instance  # type: ignore

        # Test IPv4 directly (L2 len 0)
        ipv4_pkt = b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
        FakeBuf.stored_instance = FakeBuf(FakeHeader(len(ipv4_pkt), 1, 1, 0), ipv4_pkt)  # type: ignore

        with patch("pydivert.ebpf.PydivertPacketBuffer", FakeBuf):
            ebpf_divert._ring_callback(None, 0, 0)  # type: ignore
            p = ebpf_divert._queue.pop()  # type: ignore
            assert p.ipv4 is not None

        # Test NULL/Loopback (4 bytes prefix)
        null_pkt = b"\x02\x00\x00\x00" + ipv4_pkt
        FakeBuf.stored_instance = FakeBuf(FakeHeader(len(null_pkt), 1, 1, 0), null_pkt)  # type: ignore
        with patch("pydivert.ebpf.PydivertPacketBuffer", FakeBuf):
            ebpf_divert._ring_callback(None, 0, 0)  # type: ignore
            p = ebpf_divert._queue.pop()  # type: ignore
            assert p.ipv4 is not None
            assert len(p.raw) == len(ipv4_pkt)

        # Test Ethernet (14 bytes prefix)
        eth_pkt = b"\x00" * 14 + ipv4_pkt
        FakeBuf.stored_instance = FakeBuf(FakeHeader(len(eth_pkt), 1, 1, 0), eth_pkt)  # type: ignore
        with patch("pydivert.ebpf.PydivertPacketBuffer", FakeBuf):
            ebpf_divert._ring_callback(None, 0, 0)  # type: ignore
            p = ebpf_divert._queue.pop()  # type: ignore
            assert p.ipv4 is not None


def test_ebpf_stats_mock():
    """Test _stats_impl with mocked maps."""
    with pydivert.Divert("false", interfaces=["lo"]) as w:
        ebpf_divert = w._impl
        with patch("pydivert.ebpf.libbpf") as mock_lib:
            mock_lib.bpf_object__find_map_by_name.return_value = 123
            mock_lib.bpf_map__fd.return_value = 456
            mock_lib.libbpf_num_possible_cpus.return_value = 2

            # Simulate bpf_map_lookup_elem returning [10, 20] for diverted (key 0)
            def mock_lookup(fd, key, values):
                # values is a pointer to an array of 2 uint64s
                val_ptr = ctypes.cast(values, ctypes.POINTER(ctypes.c_uint64 * 2))

                # We can't easily check key, so we use a counter
                if not hasattr(mock_lookup, "count"):
                    mock_lookup.count = 0  # type: ignore

                if mock_lookup.count == 0:  # type: ignore # diverted
                    val_ptr.contents[0] = 10
                    val_ptr.contents[1] = 20
                elif mock_lookup.count == 1:  # type: ignore # dropped
                    val_ptr.contents[0] = 5
                    val_ptr.contents[1] = 5

                mock_lookup.count += 1  # type: ignore
                return 0

            mock_lib.bpf_map_lookup_elem.side_effect = mock_lookup

            stats = ebpf_divert._stats_impl()
            assert stats["diverted"] == 30
            assert stats["dropped"] == 10
            assert stats["sniffed"] == 0


def test_ebpf_ipv6_send_loopback():
    """Test IPv6 loopback send logic with scope_id."""
    with pydivert.Divert("false", interfaces=["lo"]) as w:
        ebpf_divert = w._impl
        packet = pydivert.Packet(b"\x60\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 32)  # Dummy IPv6
        packet.dst_addr = "::1"

        ebpf_divert._raw_sock6 = MagicMock()  # type: ignore
        with patch("socket.if_nametoindex", return_value=1):
            ebpf_divert.send(packet)
            args, kwargs = ebpf_divert._raw_sock6.sendto.call_args  # type: ignore
            assert args[1][0] == "::1"
            assert args[1][3] == 1  # scope_id


def test_ebpf_close_cancels_futures():
    """Test that closing the handle cancels pending async futures."""
    with pydivert.Divert("false", interfaces=["lo"]) as w:
        ebpf_divert = w._impl
        fut = MagicMock()
        fut.done.return_value = False
        ebpf_divert._recv_futures = [fut]  # type: ignore

        ebpf_divert.close()
        fut.set_exception.assert_called()
