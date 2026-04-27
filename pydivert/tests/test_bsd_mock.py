# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import asyncio
import time
from unittest.mock import MagicMock, patch

import pytest

from pydivert.bsd import Divert
from pydivert.consts import Direction
from pydivert.packet import Packet
from pydivert.pydivert import PyDivert


@pytest.fixture
def mock_socket():
    import socket as real_socket

    original_socket = real_socket.socket

    def socket_side_effect(family, type=real_socket.SOCK_STREAM, proto=0, fileno=None):
        IPPROTO_DIVERT = getattr(real_socket, "IPPROTO_DIVERT", 258)
        if family == real_socket.AF_INET and type == real_socket.SOCK_RAW and proto == IPPROTO_DIVERT:
            mock_sock = MagicMock()

            # Default side effect: return empty data and sleep to prevent busy loop
            def default_recv(*args):
                time.sleep(0.01)
                return (b"", ("0.0.0.0", 0, 0, 0))

            mock_sock.recvfrom.side_effect = default_recv
            return mock_sock
        return original_socket(family, type, proto, fileno)

    with patch("pydivert.bsd._Socket", side_effect=socket_side_effect):
        # Mock IPPROTO_DIVERT
        with patch("socket.IPPROTO_DIVERT", 258, create=True):
            yield


@pytest.fixture
def mock_subprocess():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        yield mock_run


def test_bsd_open_close(mock_socket, mock_subprocess):
    d = Divert("tcp.DstPort == 80")
    d.open()
    assert d.is_open
    d.close()
    assert not d.is_open


def test_bsd_open_retry_port(mock_socket, mock_subprocess):
    import socket as real_socket

    original_socket = real_socket.socket
    IPPROTO_DIVERT = getattr(real_socket, "IPPROTO_DIVERT", 258)

    call_count = 0

    def side_effect(family, type=real_socket.SOCK_STREAM, proto=0, fileno=None):
        nonlocal call_count
        if family == real_socket.AF_INET and type == real_socket.SOCK_RAW and proto == IPPROTO_DIVERT:
            call_count += 1
            if call_count == 1:
                raise OSError(48, "Address already in use")
            return MagicMock()
        return original_socket(family, type, proto, fileno)

    with patch("pydivert.bsd._Socket", side_effect=side_effect):
        d = Divert("true")
        d.open()
        assert d._port == 8889
        d.close()


def test_bsd_open_fail_final(mock_socket, mock_subprocess):
    import socket as real_socket

    def side_effect(*args, **kwargs):
        if args[0] == real_socket.AF_INET and args[1] == real_socket.SOCK_RAW:
            raise OSError("Permission denied")
        return real_socket.socket(*args, **kwargs)

    with patch("pydivert.bsd._Socket", side_effect=side_effect):
        d = Divert("true")
        with pytest.raises(OSError, match="Failed to open divert socket"):
            d.open()


def test_freebsd_rules_apply(mock_socket, mock_subprocess):
    with patch("sys.platform", "freebsd14"):
        d = Divert("tcp.DstPort == 80")
        d.open()
        mock_subprocess.assert_any_call(
            ["ipfw", "add", "50", "divert", "8888", "tcp", "from", "any", "to", "any", "80"],
            check=True,
            capture_output=True,
        )
        d.close()
        mock_subprocess.assert_any_call(["ipfw", "delete", "50"], check=False, capture_output=True)


def test_freebsd_rules_fail(mock_socket, mock_subprocess):
    with patch("sys.platform", "freebsd14"):
        mock_subprocess.side_effect = OSError("ipfw error")

        d = Divert("true")
        with pytest.raises(RuntimeError, match="Failed to apply ipfw rule"):
            d.open()
        assert not d.is_open


def test_bsd_recv_logic(mock_socket, mock_subprocess):
    d = Divert("true")
    packet_data = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01"
        b"\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )

    with patch("pydivert.bsd._Socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        results = [(packet_data, ("0.0.0.0", 0, 0, 0))]

        def side_effect(*args):
            if results:
                return results.pop(0)
            d._stop_event.set()
            return (b"", ("0.0.0.0", 0, 0, 0))

        mock_sock.recvfrom.side_effect = side_effect

        d.open()
        p = d.recv()
        assert p.direction == Direction.OUTBOUND
        d.close()


def test_bsd_recv_inbound(mock_socket, mock_subprocess):
    d = Divert("true")
    packet_data = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01"
        b"\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )
    with patch("pydivert.bsd._Socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        results = [(packet_data, ("1.2.3.4", 1234, 0, 0))]

        def side_effect(*args):
            if results:
                return results.pop(0)
            d._stop_event.set()
            return (b"", ("0.0.0.0", 0, 0, 0))

        mock_sock.recvfrom.side_effect = side_effect

        d.open()
        p = d.recv()
        assert p.direction == Direction.INBOUND
        d.close()


def test_bsd_recv_filtering(mock_socket, mock_subprocess):
    d = Divert("tcp.DstPort == 80")
    packet_data_443 = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x08\x08\x08\x08"
        b"\x08\x08\x04\x04\x00\x50\x01\xbb\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )

    mock_sock = MagicMock()
    results = [(packet_data_443, ("0.0.0.0", 0, 0, 0))]

    def side_effect(*args):
        if results:
            return results.pop(0)
        d._stop_event.set()
        return (b"", ("0.0.0.0", 0, 0, 0))

    mock_sock.recvfrom.side_effect = side_effect

    d._socket = mock_sock
    d._run_loop()
    mock_sock.sendto.assert_called()


def test_bsd_send(mock_socket, mock_subprocess):
    d = Divert("true")
    packet_data = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01"
        b"\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )
    with patch("pydivert.bsd._Socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        d.open()
        p = Packet(packet_data)
        p._bsd_addr = ("1.2.3.4", 80)
        d.send(p, recalculate_checksum=False)
        mock_sock.sendto.assert_called_with(packet_data, ("1.2.3.4", 80))
        d.close()


@pytest.mark.asyncio
async def test_bsd_async_methods(mock_socket, mock_subprocess):
    d = Divert("true")
    packet_data = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01"
        b"\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )

    with patch("pydivert.bsd._Socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        results = [(packet_data, ("0.0.0.0", 0, 0, 0))]

        def side_effect(*args):
            if results:
                return results.pop(0)
            return (b"", ("0.0.0.0", 0, 0, 0))

        mock_sock.recvfrom.side_effect = side_effect

        d.open()
        p = await asyncio.wait_for(d.recv_async(), timeout=5.0)
        assert p.raw is not None
        await d.send_async(p)
        d.close()


def test_bsd_parse_filter_extended():
    d = Divert("ip.SrcAddr == 1.2.3.4 && tcp.DstPort == 80 && inbound")
    rules = d._parse_filter_to_ipfw()
    assert any("1.2.3.4" in r and "80" in r and "in" in r for r in rules)

    d2 = Divert("true")
    rules2 = d2._parse_filter_to_ipfw()
    assert any("not dst-port 22" in r for r in rules2)

    d3 = Divert("icmp")
    rules3 = d3._parse_filter_to_ipfw()
    assert any("icmp" in r for r in rules3)

    d4 = Divert("tcp.DstPort == 80 or tcp.DstPort == 8080")
    rules4 = d4._parse_filter_to_ipfw()
    assert len(rules4) == 2
    assert "80" in rules4[0] or "80" in rules4[1]
    assert "8080" in rules4[0] or "8080" in rules4[1]


def test_bsd_open_retry_exhausted(mock_socket, mock_subprocess):
    with patch("pydivert.bsd._Socket", side_effect=OSError(48, "Address already in use")):
        d = Divert("true")
        with pytest.raises(OSError, match="Failed to find a free port"):
            d.open()


def test_bsd_close_rules_fail(mock_socket, mock_subprocess):
    with patch("sys.platform", "freebsd14"):
        d = Divert("true")
        d.open()
        mock_subprocess.side_effect = Exception("ipfw delete fail")
        d.close()
        assert not d.is_open


def test_pydivert_bsd_facade(mock_socket, mock_subprocess):
    with patch("sys.platform", "freebsd14"):
        with PyDivert("true") as w:
            assert w._impl.__class__.__name__ == "Divert"
            assert w.is_open


def test_bsd_recv_closed():
    d = Divert()
    with pytest.raises(RuntimeError):
        d.recv()


def test_bsd_cleanup_all(mock_socket, mock_subprocess):
    d = Divert("true")
    d.open()
    with patch.object(d, "close", side_effect=OSError("cleanup fail")):
        Divert.cleanup_all()
    assert d in Divert._instances
    Divert._instances.remove(d)
