# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import queue
import sys
from typing import cast
from unittest.mock import MagicMock, patch

import pytest

from pydivert.consts import Direction
from pydivert.macos import MacOSDivert
from pydivert.packet import Packet
from pydivert.pydivert import PyDivert


def setup_module(module):
    """Skip all tests in this module if not running on macOS."""
    if sys.platform != "darwin":
        pytest.skip("macOS only tests")


@pytest.fixture
def mock_pfctl():
    with patch("subprocess.run") as mock_run, patch("subprocess.Popen") as mock_popen:
        mock_run.return_value = MagicMock(stdout="Status: Enabled", returncode=0)

        mock_process = MagicMock()
        mock_process.communicate.return_value = ("", "")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        yield {"run": mock_run, "popen": mock_popen}


@pytest.fixture
def mock_socket():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        # Mock IPPROTO_DIVERT
        with patch("socket.IPPROTO_DIVERT", 258, create=True):
            yield mock_sock


def test_macos_open_close(mock_pfctl, mock_socket):
    d = MacOSDivert("tcp.DstPort == 80")
    d.open()

    assert d.is_open
    mock_pfctl["run"].assert_any_call(["pfctl", "-s", "info"], capture_output=True, text=True)

    d.close()
    assert not d.is_open


def test_macos_open_pf_disabled(mock_pfctl, mock_socket):
    mock_pfctl["run"].side_effect = [
        MagicMock(stdout="Status: Disabled", returncode=0),  # pfctl -s info
        MagicMock(returncode=0),  # pfctl -e
    ]
    d = MacOSDivert("true")
    d.open()
    assert d.is_open
    mock_pfctl["run"].assert_any_call(["pfctl", "-e"], check=True, capture_output=True)
    d.close()


def test_macos_open_socket_retry(mock_pfctl, mock_socket):
    # First socket bind fails (PermissionError or similar), second succeeds
    mock_socket.bind.side_effect = [OSError("Address already in use"), None]
    d = MacOSDivert("true")
    d.open()
    assert d.is_open
    assert d._port != 0  # Should have picked another port
    d.close()


def test_macos_open_pf_fail(mock_pfctl, mock_socket):
    mock_pfctl["run"].side_effect = Exception("PF error")
    d = MacOSDivert("true")
    with pytest.raises(RuntimeError, match="Failed to configure PF"):
        d.open()
    assert not d.is_open


def test_macos_recv(mock_pfctl, mock_socket):
    d = MacOSDivert("true")
    d.open()

    packet_data = (
        b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01'
        b'\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x50\x02\x20\x00\x00\x00\x00\x00'
    )

    results = [(packet_data, ("192.168.1.1", 0)), (packet_data, ("0.0.0.0", 0))]
    def side_effect(*args):
        if results:
            return results.pop(0)
        d._stop_event.set()
        raise OSError("Stop loop")

    mock_socket.recvfrom.side_effect = side_effect

    p = d.recv()
    assert p.direction == Direction.INBOUND

    p = d.recv()
    assert p.direction == Direction.OUTBOUND
    d.close()


@pytest.mark.asyncio
async def test_macos_async_methods(mock_pfctl, mock_socket):
    d = MacOSDivert("true")
    d.open()

    packet_data = (
        b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01'
        b'\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x50\x02\x20\x00\x00\x00\x00\x00'
    )

    def side_effect(*args):
        d._stop_event.set()
        return (packet_data, ("0.0.0.0", 0))

    mock_socket.recvfrom.side_effect = side_effect

    p = await d.recv_async()
    assert p.direction == Direction.OUTBOUND

    mock_socket.sendto.return_value = len(packet_data)
    sent = await d.send_async(p)
    assert sent == len(packet_data)

    d.close()



def test_macos_parse_filter(mock_pfctl, mock_socket):
    d = MacOSDivert("tcp.DstPort == 80")
    rules = d._parse_filter_to_pf()
    assert any("proto tcp" in r for r in rules)
    assert any("port 80" in r for r in rules)
    assert any("divert-packet" in r for r in rules)

    d2 = MacOSDivert("udp.SrcPort == 53")
    rules2 = d2._parse_filter_to_pf()
    assert any("proto udp" in r for r in rules2)
    assert any("port 53" in r for r in rules2)

    d3 = MacOSDivert('ip.SrcAddr == "127.0.0.1"')
    rules3 = d3._parse_filter_to_pf()
    assert any("from 127.0.0.1" in r for r in rules3)

    d4 = MacOSDivert("icmp and loopback")
    rules4 = d4._parse_filter_to_pf()
    assert any("proto icmp" in r for r in rules4)
    assert any("on lo0" in r for r in rules4)

    d5 = MacOSDivert('ip.DstAddr == "8.8.8.8" and udp.SrcPort == 53')
    rules5 = d5._parse_filter_to_pf()
    assert any("to 8.8.8.8" in r for r in rules5)
    assert any("port 53" in r for r in rules5)


def test_macos_cleanup_all(mock_pfctl, mock_socket):
    d = MacOSDivert("true")
    d.open()
    MacOSDivert.cleanup_all()
    assert not d.is_open


def test_macos_open_already_open(mock_pfctl, mock_socket):
    d = MacOSDivert("true")
    d.open()
    with pytest.raises(RuntimeError, match="already open"):
        d.open()
    d.close()


def test_macos_open_socket_fail_final(mock_pfctl, mock_socket):
    mock_socket.bind.side_effect = OSError("Access denied")
    d = MacOSDivert("true")
    with pytest.raises(OSError, match="Failed to open divert socket"):
        d.open()


def test_macos_open_pf_rules_fail(mock_pfctl, mock_socket):
    mock_pfctl["popen"].return_value.returncode = 1
    mock_pfctl["popen"].return_value.communicate.return_value = ("", "Rules error")
    d = MacOSDivert("true")
    with pytest.raises(RuntimeError, match="Rules error"):
        d.open()


def test_macos_recv_error(mock_pfctl, mock_socket):
    d = MacOSDivert("true")
    d.open()
    # To avoid background thread block/timeout, we must let it exit or handle it
    d._stop_event.set()

    mock_socket.recvfrom.side_effect = OSError("Read error")
    with pytest.raises(OSError, match="Read error"):
        # We call the internal _run_loop one step
        d._run_loop()

    d._socket = None
    with pytest.raises(RuntimeError, match="Socket is not open."):
        d.recv()

    d = MacOSDivert("true")
    d.open()

    def concurrent_close_side_effect(*args):
        d._socket = None  # Simulate another thread closing it
        d._stop_event.set()
        raise OSError("EBADF")
    mock_socket.recvfrom.side_effect = concurrent_close_side_effect
    with pytest.raises(RuntimeError, match="Socket closed during recv"):
        # Since recv() blocks on queue, we manually trigger the error
        with patch.object(d._queue, "get", side_effect=queue.Empty):
            d.recv()
    d.close()


def test_macos_recv_filtering(mock_pfctl, mock_socket):
    d = MacOSDivert("tcp.DstPort == 80")
    d.open()

    # Packet for port 443 (should be ignored and re-sent)
    packet_data_443 = (
        b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01'
        b'\x7f\x00\x00\x01\x00\x50\x01\xbb\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x50\x02\x20\x00\x00\x00\x00\x00'
    )
    # Packet for port 80
    packet_data_80 = (
        b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01'
        b'\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x50\x02\x20\x00\x00\x00\x00\x00'
    )

    # We need to use a side_effect that eventually stops the loop
    results = [(packet_data_443, ("0.0.0.0", 0)), (packet_data_80, ("0.0.0.0", 0))]
    def side_effect(*args):
        if results:
            return results.pop(0)
        d._stop_event.set()
        raise OSError("Stop loop")

    mock_socket.recvfrom.side_effect = side_effect

    p = d.recv()
    assert p.dst_port == 80
    # verify 443 was re-sent
    mock_socket.sendto.assert_any_call(packet_data_443, ("0.0.0.0", 0))
    d.close()



def test_macos_send_fail(mock_pfctl, mock_socket):
    d = MacOSDivert("true")
    d.open()
    mock_socket.sendto.side_effect = OSError("Send failed")
    p = Packet(
        b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01'
        b'\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x50\x02\x20\x00\x00\x00\x00\x00'
    )
    with pytest.raises(OSError, match="Send failed"):
        d.send(p)
    d.close()


def test_pydivert_macos_facade(mock_pfctl, mock_socket):
    with patch("sys.platform", "darwin"):
        with PyDivert("true") as w:
            assert isinstance(w._impl, MacOSDivert)
            assert w.is_open

            packet_data = (
                b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01'
                b'\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x50\x02\x20\x00\x00\x00\x00\x00'
            )

            def side_effect(*args):
                cast(MacOSDivert, w._impl)._stop_event.set()
                return (packet_data, ("0.0.0.0", 0))

            mock_socket.recvfrom.side_effect = side_effect
            p = w.recv()
            assert p.direction == Direction.OUTBOUND

            mock_socket.sendto.return_value = len(packet_data)
            w.send(p)


@pytest.mark.asyncio
async def test_pydivert_macos_facade_async(mock_pfctl, mock_socket):
    with patch("sys.platform", "darwin"):
        async with PyDivert("true") as w:
            assert isinstance(w._impl, MacOSDivert)
            assert w.is_open

            packet_data = (
                b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01'
                b'\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x50\x02\x20\x00\x00\x00\x00\x00'
            )

            def side_effect(*args):
                cast(MacOSDivert, w._impl)._stop_event.set()
                return (packet_data, ("0.0.0.0", 0))

            mock_socket.recvfrom.side_effect = side_effect
            p = await w.recv_async()
            assert p.direction == Direction.OUTBOUND

            mock_socket.sendto.return_value = len(packet_data)
            await w.send_async(p)

