# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import asyncio
from unittest.mock import MagicMock, patch

import pytest

from pydivert.consts import Direction
from pydivert.linux import NetFilterQueue
from pydivert.packet import Packet
from pydivert.pydivert import PyDivert


@pytest.fixture
def mock_nfq():
    with patch("pydivert.linux.NFQ") as mock_nfq_cls:
        mock_nfq_instance = MagicMock()
        mock_nfq_cls.return_value = mock_nfq_instance
        yield mock_nfq_instance


@pytest.fixture
def mock_subprocess():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        yield mock_run


def test_linux_open_close(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue("tcp.DstPort == 80")
    nfq.open()
    assert nfq.is_open
    mock_subprocess.assert_any_call(
        ["iptables", "-I", "INPUT", "-p", "tcp", "--dport", "80", "-j", "NFQUEUE", "--queue-num", "0"],
        check=True,
        capture_output=True,
    )
    nfq.close()
    assert not nfq.is_open
    mock_nfq.unbind.assert_called_once()


def test_linux_open_retry_queue(mock_nfq, mock_subprocess):
    mock_nfq.bind.side_effect = [OSError("Queue already bound"), None]
    nfq = NetFilterQueue("true")
    nfq.open()
    assert nfq._queue_num == 1
    nfq.close()


def test_linux_open_fail_all(mock_nfq, mock_subprocess):
    mock_nfq.bind.side_effect = OSError("Access denied")
    nfq = NetFilterQueue("true")
    with pytest.raises(OSError, match="Failed to bind to any NFQueue"):
        nfq.open()


def test_linux_iptables_fail(mock_nfq, mock_subprocess):
    def side_effect(cmd, *args, **kwargs):
        if cmd[0] == "iptables" and "-I" in cmd:
            raise Exception("iptables error")
        return MagicMock(returncode=0)

    mock_subprocess.side_effect = side_effect
    nfq = NetFilterQueue("true")
    with pytest.raises(RuntimeError, match="Failed to add iptables rule"):
        nfq.open()
    assert not nfq.is_open


def test_linux_callback_logic(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue("tcp.DstPort == 80")
    nfq.open()
    mock_pkt = MagicMock()
    mock_pkt.get_payload.return_value = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x08\x08\x08\x08"
        b"\x08\x08\x04\x04\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )
    mock_pkt.indev = 0
    mock_pkt.outdev = 2

    nfq._callback(mock_pkt)
    p = nfq.recv()
    assert p.dst_port == 80
    assert p.direction == Direction.OUTBOUND
    assert not p.is_loopback
    nfq.close()


def test_linux_callback_loopback(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue("true")
    nfq.open()
    mock_pkt = MagicMock()
    mock_pkt.get_payload.return_value = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01"
        b"\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )
    mock_pkt.indev = 1
    mock_pkt.outdev = 1

    nfq._callback(mock_pkt)
    p = nfq.recv()
    assert p.is_loopback
    nfq.close()


def test_linux_callback_filtering(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue("tcp.DstPort == 80")
    nfq.open()

    mock_pkt_443 = MagicMock()
    mock_pkt_443.get_payload.return_value = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x08\x08\x08\x08"
        b"\x08\x08\x04\x04\x00\x50\x01\xbb\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )
    mock_pkt_443.indev = 0
    mock_pkt_443.outdev = 2
    nfq._callback(mock_pkt_443)
    mock_pkt_443.accept.assert_called_once()

    mock_pkt_80 = MagicMock()
    mock_pkt_80.get_payload.return_value = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x08\x08\x08\x08"
        b"\x08\x08\x04\x04\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )
    mock_pkt_80.indev = 0
    mock_pkt_80.outdev = 2
    nfq._callback(mock_pkt_80)
    assert not nfq._queue.empty()
    nfq.close()


def test_linux_send_accept(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue("true")
    nfq.open()
    mock_pkt = MagicMock()
    packet_data = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01"
        b"\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )
    p = Packet(packet_data)
    p._nfq_pkt = mock_pkt
    nfq.send(p)
    mock_pkt.set_payload.assert_called_once()
    mock_pkt.accept.assert_called_once()
    nfq.close()


def test_linux_send_inject(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue("true")
    nfq.open()
    p = Packet(
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01"
        b"\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__.return_value = mock_sock
        nfq.send(p, recalculate_checksum=True)
        mock_sock.sendto.assert_called_once()
    nfq.close()


@pytest.mark.asyncio
async def test_linux_async_methods(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue("true")
    nfq.open()
    mock_pkt = MagicMock()
    packet_data = (
        b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01"
        b"\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x50\x02\x20\x00\x00\x00\x00\x00"
    )
    mock_pkt.get_payload.return_value = packet_data
    mock_pkt.indev = 0
    mock_pkt.outdev = 2
    nfq._callback(mock_pkt)
    p = await asyncio.wait_for(nfq.recv_async(), timeout=5.0)
    assert p.raw == packet_data
    await nfq.send_async(p)
    mock_pkt.accept.assert_called_once()
    nfq.close()


def test_linux_cleanup_stale(mock_nfq, mock_subprocess):
    def side_effect(cmd, *args, **kwargs):
        if "-S" in cmd:
            return MagicMock(returncode=0, stdout="-A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0\n")
        return MagicMock(returncode=0)

    mock_subprocess.side_effect = side_effect
    nfq = NetFilterQueue("true", priority=0)
    nfq._cleanup_stale_rules()
    mock_subprocess.assert_any_call(
        ["iptables", "-D", "INPUT", "-p", "tcp", "--dport", "80", "-j", "NFQUEUE", "--queue-num", "0"], check=False
    )


def test_linux_parse_filter_true():
    nfq = NetFilterQueue("true")
    rules = nfq._parse_filter_to_iptables()
    assert len(rules) == 3
    assert any("22" in r[1] for r in rules)


def test_linux_remove_rules_iptables_missing(mock_nfq, mock_subprocess):
    mock_subprocess.side_effect = [MagicMock(returncode=1)]
    nfq = NetFilterQueue("true")
    nfq._applied_rules = [(["INPUT"], ["-p", "tcp"])]
    nfq._remove_rules()
    assert nfq._applied_rules == []


def test_linux_run_loop_error(mock_nfq, mock_subprocess):
    mock_nfq.run.side_effect = Exception("NFQueue loop crash")
    nfq = NetFilterQueue("true")
    nfq.open()
    with patch("pydivert.linux.logger") as mock_logger:
        nfq._run_loop()
        mock_logger.error.assert_called()
    nfq.close()


def test_linux_send_ipv6_fallback(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue("true")
    nfq.open()
    p = Packet(b"ipv6_data")
    with patch.object(p, "ipv4", False):
        nfq.send(p)
    nfq.close()


def test_linux_parse_filter_complex():
    nfq = NetFilterQueue("ip.SrcAddr == 1.2.3.4 && tcp.DstPort == 80 && inbound")
    rules = nfq._parse_filter_to_iptables()
    chains, args = rules[0]
    assert "INPUT" in chains
    assert "FORWARD" in chains
    assert "-s" in args
    assert "1.2.3.4" in args
    assert "--dport" in args
    assert "80" in args


def test_linux_parse_filter_loopback():
    nfq = NetFilterQueue("loopback")
    rules = nfq._parse_filter_to_iptables()
    assert any("-i" in r[1] and "lo" in r[1] for r in rules)
    assert any("-o" in r[1] and "lo" in r[1] for r in rules)


def test_linux_missing_lib(mock_subprocess):
    with patch("pydivert.linux.NFQ", None):
        nfq = NetFilterQueue()
        with pytest.raises(ImportError):
            nfq.open()


def test_linux_recv_closed():
    nfq = NetFilterQueue()
    with pytest.raises(RuntimeError):
        nfq.recv()


def test_pydivert_linux_facade(mock_nfq, mock_subprocess):
    with patch("sys.platform", "linux"):
        with PyDivert("true") as w:
            assert isinstance(w._impl, NetFilterQueue)
            assert w.is_open


def test_linux_cleanup_all(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue("true")
    nfq.open()
    with patch.object(nfq, "close", side_effect=Exception("cleanup fail")):
        NetFilterQueue._cleanup_all()
    assert nfq in NetFilterQueue._instances
    NetFilterQueue._instances.remove(nfq)
