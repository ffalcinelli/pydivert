# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import asyncio
import os
import queue
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("skipping linux-only tests", allow_module_level=True)

from pydivert.consts import Direction
from pydivert.linux import IptablesBackend, NetFilterQueue, NftablesBackend
from pydivert.packet import Packet
from pydivert.pydivert import PyDivert


@pytest.fixture
def mock_nfq():
    r, w = os.pipe()
    with patch("pydivert.linux.NFQ") as mock_nfq_cls:
        mock_nfq_instance = MagicMock()
        mock_nfq_cls.return_value = mock_nfq_instance
        mock_nfq_instance.get_fd.return_value = r
        yield mock_nfq_instance
    os.close(r)
    os.close(w)


@pytest.fixture
def mock_subprocess():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        yield mock_run


def test_linux_open_close(mock_nfq, mock_subprocess):
    with patch("pydivert.linux.nftables", None):
        nfq = NetFilterQueue("tcp.DstPort == 80")
        nfq.open()
        assert nfq.is_open
        # Check if iptables rule was added
        mock_subprocess.assert_any_call(
            [
                "iptables",
                "-I",
                "INPUT",
                "-m",
                "mark",
                "!",
                "--mark",
                "0x1",
                "-p",
                "tcp",
                "--dport",
                "80",
                "-j",
                "NFQUEUE",
                "--queue-num",
                "0",
            ],
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
            raise subprocess.CalledProcessError(1, cmd, stderr=b"iptables error")
        return MagicMock(returncode=0)

    mock_subprocess.side_effect = side_effect
    with patch("pydivert.linux.nftables", None):
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
    backend = IptablesBackend()
    backend._cleanup_stale_rules(0)
    mock_subprocess.assert_any_call(
        ["iptables", "-D", "INPUT", "-p", "tcp", "--dport", "80", "-j", "NFQUEUE", "--queue-num", "0"],
        check=False,
        capture_output=True,
    )


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


def test_nftables_backend_mock():
    with patch("pydivert.linux.nftables") as mock_nft:
        mock_ctx = MagicMock()
        mock_nft.Nftables.return_value = mock_ctx
        mock_ctx.cmd.return_value = (0, "", "")

        backend = NftablesBackend()
        backend.open()
        mock_ctx.cmd.assert_any_call("add table inet pydivert")

        backend.add_rule(
            0, {"proto": "tcp", "dport": "80", "srcaddr": "1.2.3.4", "dstaddr": "8.8.8.8", "loopback": True}
        )
        mock_ctx.cmd.assert_any_call(
            "add rule inet pydivert input mark != 0x1 tcp dport 80 ip saddr "
            "1.2.3.4 ip daddr 8.8.8.8 iifname lo queue num 0"
        )

        mock_ctx.cmd.return_value = (1, "", "already exists")
        backend._run_cmd("add table inet pydivert")  # Should not raise

        mock_ctx.cmd.return_value = (1, "", "real error")
        with pytest.raises(RuntimeError):
            backend._run_cmd("invalid command")

        backend.close()
        mock_ctx.cmd.assert_any_call("delete table inet pydivert")


def test_iptables_backend_ipv6(mock_subprocess):
    backend = IptablesBackend()
    backend.add_rule(0, {"srcaddr": "::1"})
    mock_subprocess.assert_any_call(
        [
            "ip6tables",
            "-I",
            "INPUT",
            "-m",
            "mark",
            "!",
            "--mark",
            "0x1",
            "-s",
            "::1",
            "-j",
            "NFQUEUE",
            "--queue-num",
            "0",
        ],
        check=True,
        capture_output=True,
    )


def test_iptables_backend_loopback(mock_subprocess):
    backend = IptablesBackend()
    backend.add_rule(0, {"loopback": True})
    # Check if -i lo was used in INPUT
    mock_subprocess.assert_any_call(
        [
            "iptables",
            "-I",
            "INPUT",
            "-m",
            "mark",
            "!",
            "--mark",
            "0x1",
            "-i",
            "lo",
            "-j",
            "NFQUEUE",
            "--queue-num",
            "0",
        ],
        check=True,
        capture_output=True,
    )
    # Check if -o lo was used in OUTPUT
    mock_subprocess.assert_any_call(
        [
            "iptables",
            "-I",
            "OUTPUT",
            "-m",
            "mark",
            "!",
            "--mark",
            "0x1",
            "-o",
            "lo",
            "-j",
            "NFQUEUE",
            "--queue-num",
            "0",
        ],
        check=True,
        capture_output=True,
    )


def test_netfilterqueue_async_loop(mock_nfq, mock_subprocess):
    with patch("asyncio.get_running_loop") as mock_loop_get:
        mock_loop = MagicMock()
        mock_loop_get.return_value = mock_loop
        nfq = NetFilterQueue()
        nfq.open()
        mock_loop.add_reader.assert_called_once()
        nfq._on_fd_ready()
        mock_nfq.run.assert_called_with(block=False)

        # Test error in reader
        mock_nfq.run.side_effect = Exception("error")
        nfq._on_fd_ready()  # Should log but not raise

        nfq.close()
        mock_loop.remove_reader.assert_called_once()


def test_netfilterqueue_recv_async_drain(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue()
    nfq.open()  # Need to open for recv_async to work
    # Put something in sync queue
    p = Packet(b"data")
    nfq._queue.put(p)

    async def run_test():
        p_async = await nfq.recv_async()
        assert p_async.raw == b"data"

    loop = asyncio.new_event_loop()
    loop.run_until_complete(run_test())
    nfq.close()


def test_netfilterqueue_recv_async_timeout(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue()
    nfq.open()

    async def run_test():
        with pytest.raises(asyncio.TimeoutError):
            await nfq.recv_async(timeout=0.01)

    loop = asyncio.new_event_loop()
    loop.run_until_complete(run_test())
    nfq.close()


def test_netfilterqueue_send_error(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue()
    nfq.open()
    p = Packet(b"data")
    p._nfq_pkt = MagicMock()
    p._nfq_pkt.accept.side_effect = Exception("fail")
    nfq.send(p)  # Should log but not raise

    p2 = Packet(b"data")
    with patch("socket.socket") as mock_sock:
        mock_sock.return_value.__enter__.return_value.sendto.side_effect = Exception("fail")
        nfq.send(p2)  # Should log but not raise
    nfq.close()


def test_netfilterqueue_recv_timeout(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue()
    nfq.open()
    with pytest.raises(queue.Empty):
        nfq._queue.get = MagicMock(side_effect=queue.Empty)  # type: ignore
        nfq.recv(timeout=0.01)
    nfq.close()


def test_netfilterqueue_recv_closed_loop(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue()
    nfq.open()
    nfq.close()
    with pytest.raises(RuntimeError):
        nfq.recv()


def test_netfilterqueue_send_async(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue()
    nfq.open()
    p = Packet(b"data")
    loop = asyncio.new_event_loop()
    loop.run_until_complete(nfq.send_async(p))
    nfq.close()


def test_iptables_backend_failure(mock_subprocess):
    backend = IptablesBackend()
    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "iptables", stderr=b"err")):
        with pytest.raises(RuntimeError):
            backend.add_rule(0, {"proto": "tcp"})


def test_nftables_backend_complex_rules():
    with patch("pydivert.linux.nftables") as mock_nft:
        mock_ctx = MagicMock()
        mock_nft.Nftables.return_value = mock_ctx
        mock_ctx.cmd.return_value = (0, "", "")
        backend = NftablesBackend()

        # Test ipv6 and inbound
        backend.add_rule(0, {"proto": "udp", "sport": "123", "srcaddr": "::1", "direction": "inbound"})
        mock_ctx.cmd.assert_any_call("add rule inet pydivert input mark != 0x1 udp sport 123 ip6 saddr ::1 queue num 0")

        # Test outbound
        backend.add_rule(0, {"direction": "outbound"})
        mock_ctx.cmd.assert_any_call("add rule inet pydivert output mark != 0x1 queue num 0")


def test_netfilterqueue_open_firewall_error(mock_nfq, mock_subprocess):
    # Test that open() continues even if firewall setup fails
    with patch("pydivert.linux.transpile_to_rules", side_effect=Exception("parse error")):
        nfq = NetFilterQueue()
        nfq.open()
        assert nfq.is_open
        nfq.close()


def test_netfilterqueue_close_backend_error(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue()
    nfq.open()
    nfq._backend.close = MagicMock(side_effect=Exception("close fail"))  # type: ignore
    nfq.close()  # Should not raise


def test_netfilterqueue_open_firewall_coverage(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue("true")
    assert nfq._backend is not None
    nfq.open()  # This should hit 254-261
    nfq.close()


def test_netfilterqueue_send_closed_v2(mock_nfq):
    nfq = NetFilterQueue()
    # Ensure it's closed
    nfq._nfqueue = None
    with pytest.raises(RuntimeError, match="handle is not open"):
        nfq.send(Packet(b"data"))


def test_netfilterqueue_recv_empty_coverage(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue()
    nfq.open()
    nfq._queue.get = MagicMock(side_effect=queue.Empty)  # type: ignore
    # This will trigger 365
    with pytest.raises(queue.Empty):
        nfq.recv(timeout=0.01)
    nfq.close()
    # Now it's closed, 366-367
    with pytest.raises(RuntimeError):
        nfq.recv(timeout=0.01)


def test_nftables_backend_open_error():
    with patch("pydivert.linux.nftables") as mock_nft:
        mock_ctx = MagicMock()
        mock_nft.Nftables.return_value = mock_ctx
        mock_ctx.cmd.side_effect = [(1, "", "err"), (0, "", ""), (0, "", ""), (0, "", ""), (0, "", "")]
        backend = NftablesBackend()
        backend.open()


def test_iptables_backend_add_rule_various(mock_subprocess):
    backend = IptablesBackend()
    backend.add_rule(0, {"proto": "tcp", "dport": "80", "srcaddr": "1.1.1.1", "dstaddr": "2.2.2.2"})
    mock_subprocess.assert_any_call(
        [
            "iptables",
            "-I",
            "INPUT",
            "-m",
            "mark",
            "!",
            "--mark",
            "0x1",
            "-p",
            "tcp",
            "--dport",
            "80",
            "-s",
            "1.1.1.1",
            "-d",
            "2.2.2.2",
            "-j",
            "NFQUEUE",
            "--queue-num",
            "0",
        ],
        check=True,
        capture_output=True,
    )


def test_iptables_backend_cleanup_delete(mock_subprocess):
    def side_effect(cmd, *args, **kwargs):
        if "-S" in cmd:
            return MagicMock(returncode=0, stdout="-A INPUT --queue-num 0\n-A OUTPUT --queue-num 0\n")
        return MagicMock(returncode=0)

    mock_subprocess.side_effect = side_effect
    backend = IptablesBackend()
    backend._cleanup_stale_rules(0)
    # Check if delete was called twice
    assert mock_subprocess.call_count > 2


def test_nftables_backend_open_fatal_error():
    with patch("pydivert.linux.nftables") as mock_nft:
        mock_ctx = MagicMock()
        mock_nft.Nftables.return_value = mock_ctx
        mock_ctx.cmd.side_effect = Exception("fatal")
        backend = NftablesBackend()
        with pytest.raises(Exception, match="fatal"):
            backend.open()


def test_nftables_backend_proto_only():
    with patch("pydivert.linux.nftables") as mock_nft:
        mock_ctx = MagicMock()
        mock_nft.Nftables.return_value = mock_ctx
        mock_ctx.cmd.return_value = (0, "", "")
        backend = NftablesBackend()
        backend.add_rule(0, {"proto": "icmp"})
        mock_ctx.cmd.assert_any_call("add rule inet pydivert input mark != 0x1 icmp queue num 0")


def test_netfilterqueue_init_nftables_error(mock_nfq, mock_subprocess):
    with patch("pydivert.linux.NftablesBackend", side_effect=Exception("init fail")):
        nfq = NetFilterQueue()
        assert isinstance(nfq._backend, IptablesBackend)


def test_iptables_backend_cleanup_exception(mock_subprocess):
    mock_subprocess.side_effect = Exception("crash")
    backend = IptablesBackend()
    backend._cleanup_stale_rules(0)  # Should pass due to except: pass


def test_netfilterqueue_open_firewall_runtime_error(mock_nfq, mock_subprocess):
    with patch("pydivert.linux.nftables", None):
        nfq = NetFilterQueue()
        # Mock add_rule to raise RuntimeError
        nfq._backend.add_rule = MagicMock(side_effect=RuntimeError("Failed to add iptables rule"))  # type: ignore
        with pytest.raises(RuntimeError, match="Failed to add iptables rule"):
            nfq.open()
        assert not nfq.is_open


def test_netfilterqueue_recv_empty_not_open(mock_nfq):
    nfq = NetFilterQueue()
    # Mocking is_open to False but queue not empty
    nfq._nfqueue = None
    with pytest.raises(RuntimeError, match="handle is not open"):
        nfq.recv()


def test_nftables_backend_import_error():
    with patch("pydivert.linux.nftables", None):
        with pytest.raises(ImportError):
            NftablesBackend()


def test_netfilterqueue_recv_empty_not_open_v3(mock_nfq):
    nfq = NetFilterQueue()
    nfq._queue.get = MagicMock(side_effect=queue.Empty)  # type: ignore
    nfq._nfqueue = None
    with pytest.raises(RuntimeError):
        nfq.recv()


def test_netfilterqueue_close_reader_removal_error(mock_nfq, mock_subprocess):
    with patch("asyncio.get_running_loop") as mock_get_loop:
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop
        nfq = NetFilterQueue()
        nfq.open()
        mock_loop.remove_reader.side_effect = Exception("err")
        nfq.close()  # Should not raise


def test_netfilterqueue_on_fd_ready_closed(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue()
    nfq.open()
    nfq._nfqueue.run.side_effect = Exception("err")
    nfq._nfqueue = None  # closed
    nfq._on_fd_ready()  # Should not log


@pytest.mark.asyncio
async def test_netfilterqueue_recv_async_closed_v2(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue()
    nfq.open()
    nfq.close()
    with pytest.raises(RuntimeError):
        await nfq.recv_async()


def test_netfilterqueue_open_firewall_re_raise(mock_nfq, mock_subprocess):
    # Test that open() re-raises if firewall setup fails and not open
    mock_nfq.bind.side_effect = Exception("fail")
    with patch("pydivert.linux.transpile_to_rules", side_effect=Exception("parse error")):
        nfq = NetFilterQueue()
        with pytest.raises(Exception, match="fail"):
            nfq.open()


def test_netfilterqueue_close_backend_error_v4(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue()
    nfq.open()
    # Mocking self._backend.close to raise
    with patch.object(nfq._backend, "close", side_effect=Exception("err")):
        nfq.close()


def test_netfilterqueue_recv_empty_not_open_v5(mock_nfq):
    nfq = NetFilterQueue()
    # Mocking is_open to False and queue empty
    nfq._nfqueue = None
    nfq._queue.get = MagicMock(side_effect=queue.Empty)  # type: ignore
    with pytest.raises(RuntimeError):
        nfq.recv()


def test_netfilterqueue_recv_async_drain_error_v2(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue()
    nfq.open()
    nfq._queue.get_nowait = MagicMock(side_effect=Exception("drain err"))  # type: ignore

    async def run_test():
        await nfq.recv_async(timeout=0.01)

    loop = asyncio.new_event_loop()
    with pytest.raises(Exception, match="drain err"):
        loop.run_until_complete(run_test())
    nfq.close()


def test_netfilterqueue_close_reader_error_v2(mock_nfq, mock_subprocess):
    with patch("asyncio.get_running_loop") as mock_get_loop:
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop
        nfq = NetFilterQueue()
        nfq.open()
        mock_loop.remove_reader.side_effect = Exception("err")
        nfq.close()


def test_netfilterqueue_recv_async_drain_empty(mock_nfq, mock_subprocess):
    nfq = NetFilterQueue()
    nfq.open()
    nfq._queue.get_nowait = MagicMock(side_effect=queue.Empty)  # type: ignore

    async def run_test():
        with pytest.raises(asyncio.TimeoutError):
            await nfq.recv_async(timeout=0.01)

    loop = asyncio.new_event_loop()
    loop.run_until_complete(run_test())
    nfq.close()
