# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import asyncio
from unittest.mock import MagicMock, patch

import pytest

from pydivert.bsd import Divert
from pydivert.consts import Direction
from pydivert.packet import Packet
from pydivert.pydivert import PyDivert


@pytest.fixture
def mock_socket():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        # Mock IPPROTO_DIVERT
        with patch("socket.IPPROTO_DIVERT", 258, create=True):
            yield mock_sock


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
    mock_socket.close.assert_called_once()


def test_bsd_open_retry_port(mock_socket, mock_subprocess):
    # First bind fails, second succeeds
    mock_socket.bind.side_effect = [OSError(48, "Address already in use"), None]
    d = Divert("true")
    d.open()
    assert d._port == 8889
    d.close()


def test_bsd_open_fail_final(mock_socket, mock_subprocess):
    mock_socket.bind.side_effect = OSError("Permission denied")
    d = Divert("true")
    with pytest.raises(OSError, match="Failed to open divert socket"):
        d.open()


def test_freebsd_rules_apply(mock_socket, mock_subprocess):
    with patch("sys.platform", "freebsd14"):
        d = Divert("tcp.DstPort == 80")
        d.open()
        mock_subprocess.assert_any_call(
            ["ipfw", "add", "50", "divert", "8888", "tcp", "from", "any", "to", "any", "80"],
            check=True, capture_output=True
        )
        d.close()
        mock_subprocess.assert_any_call(["ipfw", "delete", "50"], check=False, capture_output=True)


def test_freebsd_rules_fail(mock_socket, mock_subprocess):
    with patch("sys.platform", "freebsd14"):
        mock_subprocess.side_effect = Exception("ipfw error")
        d = Divert("true")
        with pytest.raises(RuntimeError, match="Failed to apply ipfw rule"):
            d.open()
        assert not d.is_open


def test_bsd_recv_logic(mock_socket, mock_subprocess):
    d = Divert("true")
    packet_data = (
        b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01'
        b'\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x50\x02\x20\x00\x00\x00\x00\x00'
    )

    # We run the loop once manually or mock it
    def side_effect(*args):
        if d._stop_event.is_set():
             raise OSError("Loop stopped")
        d._stop_event.set()
        return (packet_data, ("1.2.3.4", 0, 0, 0))
    mock_socket.recvfrom.side_effect = side_effect

    d.open()
    p = d.recv()
    assert p.direction == Direction.OUTBOUND
    d.close()


def test_bsd_recv_inbound(mock_socket, mock_subprocess):
    d = Divert("true")
    packet_data = b"data"
    # port != 0 means inbound
    def side_effect(*args):
        if d._stop_event.is_set():
             raise OSError("Loop stopped")
        d._stop_event.set()
        return (packet_data, ("1.2.3.4", 1234, 0, 0))
    mock_socket.recvfrom.side_effect = side_effect

    d.open()
    p = d.recv()
    assert p.direction == Direction.INBOUND
    d.close()


def test_bsd_recv_filtering(mock_socket, mock_subprocess):
    d = Divert("tcp.DstPort == 80")

    packet_data_443 = (
        b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01'
        b'\x7f\x00\x00\x01\x00\x50\x01\xbb\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x50\x02\x20\x00\x00\x00\x00\x00'
    )

    def side_effect(*args):
        if d._stop_event.is_set():
             raise OSError("Loop stopped")
        d._stop_event.set()
        return (packet_data_443, ("1.2.3.4", 0, 0, 0))
    mock_socket.recvfrom.side_effect = side_effect

    d.open()
    # Let it run for a bit
    import time
    time.sleep(0.1)
    d.close()
    mock_socket.sendto.assert_called()


def test_bsd_send(mock_socket, mock_subprocess):
    d = Divert("true")
    d.open()
    p = Packet(b"data")
    p._bsd_addr = ("1.2.3.4", 0, 0, 0)
    d.send(p, recalculate_checksum=True)
    mock_socket.sendto.assert_called()


@pytest.mark.asyncio
async def test_bsd_async_methods(mock_socket, mock_subprocess):
    d = Divert("true")

    packet_data = (
        b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01'
        b'\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x50\x02\x20\x00\x00\x00\x00\x00'
    )

    def side_effect(*args):
        if d._stop_event.is_set():
             raise OSError("Loop stopped")
        return (packet_data, ("1.2.3.4", 0, 0, 0))

    mock_socket.recvfrom.side_effect = side_effect
    d.open()

    p = await asyncio.wait_for(d.recv_async(), timeout=5.0)
    assert p.raw is not None
    await d.send_async(p)
    d.close()


def test_bsd_parse_filter():
    # Use && and ||
    d = Divert('ip.SrcAddr == 1.2.3.4 && tcp.DstPort == 80 && inbound')
    rules = d._parse_filter_to_ipfw()
    # Check that any rule contains the components
    assert any("1.2.3.4" in r and "80" in r and "in" in r for r in rules)


def test_bsd_parse_filter_true():
    d = Divert('true')
    rules = d._parse_filter_to_ipfw()
    assert any("not dst-port 22" in r for r in rules)


def test_pydivert_bsd_facade(mock_socket, mock_subprocess):
    with patch("sys.platform", "freebsd14"):
        with PyDivert("true") as w:
            assert isinstance(w._impl, Divert)
            assert w.is_open

def test_bsd_recv_closed():
    d = Divert()
    with pytest.raises(RuntimeError):
        d.recv()

def test_bsd_open_retry_exhausted(mock_socket, mock_subprocess):
    # Bind fails 100 times
    mock_socket.bind.side_effect = OSError(48, "Address already in use")
    d = Divert("true")
    with pytest.raises(OSError, match="Failed to find a free port"):
        d.open()

def test_bsd_parse_filter_extended():
    d1 = Divert("tcp.SrcPort == 53")
    rules1 = d1._parse_filter_to_ipfw()
    assert "53" in rules1[0]

    d2 = Divert("icmp")
    rules2 = d2._parse_filter_to_ipfw()
    assert "icmp" in rules2[0]

def test_bsd_close_rules_fail(mock_socket, mock_subprocess):
    with patch("sys.platform", "freebsd14"):
        d = Divert("true")
        d.open()
        mock_subprocess.side_effect = Exception("ipfw delete fail")
        d.close() # Should not raise
        assert not d.is_open

def test_bsd_send_tuple_padding(mock_socket, mock_subprocess):
    d = Divert("true")
    d.open()
    p = Packet(b"data")
    # Simulate a 2-tuple (ip, port) that needs padding to 4-tuple for FreeBSD
    p._bsd_addr = ("1.2.3.4", 80)
    d.send(p)
    # The last 2 elements should be padded with 0
    mock_socket.sendto.assert_called_with(b"data", ("1.2.3.4", 80, 0, 0))

