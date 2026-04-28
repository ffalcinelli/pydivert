# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import asyncio
import queue
import time
from unittest.mock import MagicMock, patch

import pytest

from pydivert.consts import Direction
from pydivert.macos import MacOSDivert
from pydivert.packet import Packet
from pydivert.pydivert import PyDivert


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
    import socket as real_socket

    original_socket = real_socket.socket

    def socket_side_effect(family, type=real_socket.SOCK_STREAM, proto=0, fileno=None):
        IPPROTO_DIVERT = getattr(real_socket, "IPPROTO_DIVERT", 258)
        if family == real_socket.AF_INET and type == real_socket.SOCK_RAW and proto == IPPROTO_DIVERT:
            mock_sock = MagicMock()

            # Default side effect: return empty data and sleep to prevent busy loop
            def default_recv(*args):
                time.sleep(0.01)
                return (b"", ("0.0.0.0", 0))

            mock_sock.recvfrom.side_effect = default_recv
            return mock_sock
        return original_socket(family, type, proto, fileno)

    with patch("pydivert.macos._Socket", side_effect=socket_side_effect):
        # Mock IPPROTO_DIVERT
        with patch("socket.IPPROTO_DIVERT", 258, create=True):
            yield


def test_macos_open_close(mock_pfctl, mock_socket):
    with patch("sys.platform", "darwin"):
        d = MacOSDivert("tcp.DstPort == 80")
        d.open()
        assert d.is_open
        mock_pfctl["run"].assert_any_call(["pfctl", "-s", "info"], capture_output=True, text=True)
        d.close()
        assert not d.is_open


def test_macos_open_pf_disabled(mock_pfctl, mock_socket):
    with patch("sys.platform", "darwin"):
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
            mock_sock = MagicMock()
            # Prevent background thread from crashing
            mock_sock.recvfrom.side_effect = lambda *args: time.sleep(0.01) or (b"", ("0.0.0.0", 0))
            return mock_sock
        return original_socket(family, type, proto, fileno)

    with patch("sys.platform", "darwin"):
        with patch("pydivert.macos._Socket", side_effect=side_effect):
            d = MacOSDivert("true")
            d.open()
            assert d.is_open
            assert d._port == 8889
            d.close()


def test_macos_open_socket_retry_fail(mock_pfctl, mock_socket):
    with patch("sys.platform", "darwin"):
        with patch("pydivert.macos._Socket", side_effect=OSError(48, "Address already in use")):
            d = MacOSDivert("true")
            with pytest.raises(OSError, match="Failed to find a free port"):
                d.open()


def test_macos_open_pf_fail(mock_pfctl, mock_socket):
    with patch("sys.platform", "darwin"):
        mock_pfctl["run"].side_effect = OSError("PF error")

        d = MacOSDivert("true")
        with pytest.raises(RuntimeError, match="Failed to configure PF"):
            d.open()
        assert not d.is_open


def test_macos_recv(mock_pfctl, mock_socket):
    packet_data = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x08\x08\x08\x08"
        b"\x08\x08\x04\x04\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )

    with patch("sys.platform", "darwin"):
        d = MacOSDivert("true")
        with patch("pydivert.macos._Socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            results = [(packet_data, ("192.168.1.1", 0)), (packet_data, ("0.0.0.0", 0))]

            def side_effect(*args):
                if results:
                    return results.pop(0)
                d._stop_event.set()
                return (b"", ("0.0.0.0", 0))

            mock_sock.recvfrom.side_effect = side_effect

            d.open()
            p = d.recv()
            assert p.direction == Direction.INBOUND
            p = d.recv()
            assert p.direction == Direction.OUTBOUND
            d.close()


@pytest.mark.asyncio
async def test_macos_async_methods(mock_pfctl, mock_socket):
    packet_data = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01"
        b"\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )

    with patch("sys.platform", "darwin"):
        d = MacOSDivert("true")
        with patch("pydivert.macos._Socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            results = [(packet_data, ("0.0.0.0", 0))]

            def side_effect(*args):
                if results:
                    return results.pop(0)
                d._stop_event.set()
                return (b"", ("0.0.0.0", 0))

            mock_sock.recvfrom.side_effect = side_effect
            d.open()

            p = await asyncio.wait_for(d.recv_async(), timeout=5.0)
            assert p.direction == Direction.OUTBOUND

            mock_sock.sendto.return_value = len(packet_data)
            sent = await d.send_async(p)
            assert sent == len(packet_data)
            d.close()


def test_macos_parse_filter_extended(mock_pfctl, mock_socket):
    with patch("sys.platform", "darwin"):
        d = MacOSDivert("tcp.DstPort == 80 && inbound")
        rules = d._parse_filter_to_pf()
        assert any("proto tcp" in r for r in rules)
        assert any("port 80" in r for r in rules)
        assert all(" in " in r for r in rules)

        d2 = MacOSDivert("icmp")
        rules2 = d2._parse_filter_to_pf()
        assert any("proto icmp" in r for r in rules2)

        d3 = MacOSDivert("ip.SrcAddr == 1.1.1.1")
        rules3 = d3._parse_filter_to_pf()
        assert any("from 1.1.1.1" in r for r in rules3)


def test_macos_cleanup_all(mock_pfctl, mock_socket):
    with patch("sys.platform", "darwin"):
        d = MacOSDivert("true")
        d.open()
        with patch.object(d, "close", side_effect=OSError("cleanup fail")):
            MacOSDivert.cleanup_all()
        assert d in MacOSDivert._instances
        MacOSDivert._instances.remove(d)


def test_macos_open_already_open(mock_pfctl, mock_socket):
    with patch("sys.platform", "darwin"):
        d = MacOSDivert("true")
        d.open()
        with pytest.raises(RuntimeError, match="already open"):
            d.open()
        d.close()


def test_macos_open_pf_rules_fail(mock_pfctl, mock_socket):
    with patch("sys.platform", "darwin"):
        mock_pfctl["popen"].return_value.returncode = 1
        mock_pfctl["popen"].return_value.communicate.return_value = ("", "Rules error")
        d = MacOSDivert("true")
        with pytest.raises(RuntimeError, match="Rules error"):
            d.open()


def test_macos_recv_error(mock_pfctl, mock_socket):
    with patch("sys.platform", "darwin"):
        d = MacOSDivert("true")
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = OSError("Read error")
        d._socket = mock_sock
        # _run_loop now breaks on OSError instead of re-raising it
        d._run_loop()

        d._socket = None
        with pytest.raises(RuntimeError, match="handle is not open"):
            d.recv()


def test_macos_run_loop_queue_full(mock_pfctl, mock_socket):
    with patch("sys.platform", "darwin"):
        d = MacOSDivert("true")
        # Small queue for test
        d._queue = queue.Queue(maxsize=1)
        valid_packet_data = (
            b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01"
            b"\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x50\x02\x20\x00\x00\x00\x00\x00"
        )
        d._queue.put(Packet(valid_packet_data))

        packet_data = valid_packet_data
        mock_sock = MagicMock()
        results = [(packet_data, ("1.2.3.4", 0))]

        def side_effect(*args):
            if results:
                return results.pop(0)
            d._stop_event.set()
            return (b"", ("0.0.0.0", 0))

        mock_sock.recvfrom.side_effect = side_effect

        d._socket = mock_sock
        d._run_loop()
        mock_sock.sendto.assert_any_call(packet_data, ("1.2.3.4", 0))


def test_macos_send_fail(mock_pfctl, mock_socket):
    with patch("sys.platform", "darwin"):
        d = MacOSDivert("true")
        with patch("pydivert.macos._Socket") as mock_sock_cls:
            mock_sock = MagicMock()
            # Prevent background thread from crashing
            mock_sock.recvfrom.side_effect = lambda *args: time.sleep(0.01) or (b"", ("0.0.0.0", 0))
            mock_sock_cls.return_value = mock_sock
            mock_sock.sendto.side_effect = OSError("Send failed")
            d.open()
            p = Packet(
                b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01"
                b"\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x50\x02\x20\x00\x00\x00\x00\x00"
            )
            with pytest.raises(OSError, match="Send failed"):
                d.send(p)
            d.close()


def test_pydivert_macos_facade(mock_pfctl, mock_socket):
    packet_data = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01"
        b"\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )

    with patch("pydivert.macos._Socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        results = [(packet_data, ("0.0.0.0", 0))]

        def side_effect(*args):
            if results:
                return results.pop(0)
            time.sleep(0.01)
            return (b"", ("0.0.0.0", 0))

        mock_sock.recvfrom.side_effect = side_effect

        with patch("sys.platform", "darwin"):
            with PyDivert("true") as w:
                assert isinstance(w._impl, MacOSDivert)
                assert w.is_open
                p = w.recv()
                assert p.direction == Direction.OUTBOUND
                w.close()
