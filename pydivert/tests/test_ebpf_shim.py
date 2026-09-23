# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
"""
Unit tests of the Linux backend (pydivert.ebpf) against a fake libebpfdivert.

They run anywhere without privileges: the fake implements the C entry points
with the same ctypes calling convention, so what is tested is the shim itself
(argument marshalling, error mapping, Packet construction, asyncio readiness).
"""

import asyncio
import ctypes
import errno
import os
import sys
from unittest.mock import patch

import pytest

import pydivert.ebpf as ebpf
from pydivert.consts import Direction, Flag, Layer, Param
from pydivert.packet import Packet

UDP_PACKET = (
    bytes.fromhex(
        "4500002400004000401100007f0000017f000001"  # IPv4 127.0.0.1 -> 127.0.0.1, UDP
        "b05a303900100000"  # 45146 -> 12345, len 16
    )
    + b"hello-lo"
)


def _deref(ref):
    return ref._obj


class FakeLib:
    """Python stand-in for libebpfdivert (see pydivert/bpf/__init__.py)."""

    def __init__(self):
        self.opened = []
        self.closed = []
        self.sent = []
        self.params = {0: 4096, 1: 2000, 2: 4194304}
        self.queue: list[tuple[bytes, dict]] = []
        self.recv_error = 0
        self.open_errno = 0
        self.compile_error = None
        self.shutdowns = []
        self.unregistered = 0
        self.checksummed = 0
        self.rfd, self.wfd = os.pipe()

    # lifecycle
    def ebpfdivert_open(self, filt, layer, prio, flags, opts):
        o = _deref(opts)
        names = []
        if o.ifnames:
            i = 0
            while o.ifnames[i]:
                names.append(o.ifnames[i].decode())
                i += 1
        self.opened.append((filt.decode(), layer, prio, flags, names, o.ring_bytes))
        if self.open_errno:
            ctypes.set_errno(self.open_errno)
            return None
        return 0x1234

    def ebpfdivert_close(self, h):
        self.closed.append(h)
        return 0

    def ebpfdivert_get_event_fd(self, h):
        return self.rfd

    def ebpfdivert_shutdown(self, h, how):
        self.shutdowns.append(how)
        return 0

    def ebpfdivert_unregister(self):
        self.unregistered += 1
        return 0

    # receive
    def push(self, data: bytes, **fields):
        self.queue.append((data, fields))
        os.write(self.wfd, b"x")

    def ebpfdivert_recv(self, h, buf, buflen, recv_len, addr, timeout_ms):
        self.last_timeout = timeout_ms
        if self.recv_error:
            return -self.recv_error
        if not self.queue:
            return -errno.EAGAIN
        os.read(self.rfd, 1)  # one byte per queued packet: never blocks
        data, fields = self.queue.pop(0)
        if len(data) > buflen:
            return -errno.ENOBUFS
        ctypes.memmove(buf, data, len(data))
        _deref(recv_len).value = len(data)
        a = _deref(addr)
        a.Layer = fields.get("layer", 0)
        a.Outbound = fields.get("outbound", 1)
        a.Loopback = fields.get("loopback", 0)
        a.Impostor = fields.get("impostor", 0)
        a.Sniffed = fields.get("sniffed", 0)
        a.Timestamp = fields.get("timestamp", 42)
        a.u.Network.IfIdx = fields.get("ifidx", 7)
        a.u.Reserved3[5] = 0xDEADBEEF  # opaque re-injection context must survive
        return 0

    # send
    def ebpfdivert_send(self, h, buf, length, send_len, addr):
        a = _deref(addr)
        self.sent.append((bytes(buf[:length]), a.Outbound, a.u.Network.IfIdx, a.u.Reserved3[5]))
        _deref(send_len).value = length
        return 0

    def ebpfdivert_helper_calc_checksums(self, buf, length, addr, flags):
        self.checksummed += 1
        return 0

    # params & stats
    def ebpfdivert_get_param(self, h, param, value):
        if param not in self.params:
            return -errno.EINVAL
        _deref(value).value = self.params[param]
        return 0

    def ebpfdivert_set_param(self, h, param, value):
        if param not in self.params or value < 1:
            return -errno.EINVAL
        self.params[param] = value
        return 0

    def ebpfdivert_get_handle_stats(self, h, values, n):
        for i in range(n):
            values[i] = i + 1
        return n

    # helpers
    def ebpfdivert_helper_compile_filter(self, filt, layer, msg, pos):
        if self.compile_error:
            _deref(msg).value = self.compile_error[0].encode()
            _deref(pos).value = self.compile_error[1]
            return -errno.EINVAL
        return 0

    def ebpfdivert_strerror(self, err):
        return os.strerror(abs(err)).encode()


@pytest.fixture
def lib():
    fake = FakeLib()
    with (
        patch.object(ebpf, "libebpfdivert", fake),
        patch("pydivert.bpf.libebpfdivert", fake),
    ):
        yield fake
    os.close(fake.rfd)
    os.close(fake.wfd)


def test_open_marshalling(lib):
    h = ebpf.EBPFDivert(
        "tcp.DstPort == 80", Layer.NETWORK_FORWARD, 100, Flag.SNIFF, interfaces=["eth0", "lo"], ring_bytes=1 << 20
    )
    h.open()
    assert lib.opened == [("tcp.DstPort == 80", Layer.NETWORK_FORWARD, 100, Flag.SNIFF, ["eth0", "lo"], 1 << 20)]
    h.close()
    assert lib.closed == [0x1234]


def test_open_errors(lib):
    lib.open_errno = errno.EINVAL
    lib.compile_error = ("Filter expression parse error", 9)
    with pytest.raises(OSError, match="position 9"):
        ebpf.EBPFDivert("tcp and (").open()
    lib.compile_error = None
    lib.open_errno = errno.EOPNOTSUPP
    with pytest.raises(NotImplementedError):
        ebpf.EBPFDivert("true", Layer.REFLECT).open()
    lib.open_errno = errno.EPERM
    with pytest.raises(PermissionError):
        ebpf.EBPFDivert("true").open()


def test_missing_library():
    with patch.object(ebpf, "libebpfdivert", None):
        assert not ebpf.EBPFDivert.is_registered()
        ebpf.EBPFDivert.unregister()
        with pytest.raises(ImportError):
            ebpf.EBPFDivert("true").open()


def test_check_filter_and_unregister(lib):
    assert ebpf.EBPFDivert.check_filter("tcp") == (True, 0, "")
    lib.compile_error = ("Unexpected token", 4)
    assert ebpf.EBPFDivert.check_filter("tcp )") == (False, 4, "Unexpected token")
    ebpf.EBPFDivert.unregister()
    assert lib.unregistered == 1
    assert ebpf.EBPFDivert.is_registered()


def test_recv_builds_packet(lib):
    with ebpf.EBPFDivert("udp") as h:
        lib.push(UDP_PACKET, outbound=1, loopback=1, ifidx=1)
        p = h.recv(timeout=0.5)
        assert lib.last_timeout == 500
        assert isinstance(p, Packet)
        assert p.direction == Direction.OUTBOUND
        assert p.is_loopback
        assert p.interface == (1, 0)
        assert p.dst_port == 12345
        assert bytes(p.raw) == UDP_PACKET
        lib.push(UDP_PACKET)
        h.recv()
        assert lib.last_timeout == -1


def test_recv_errors(lib):
    with ebpf.EBPFDivert("udp") as h:
        with pytest.raises(TimeoutError):
            h.recv(timeout=0)
        lib.recv_error = errno.ESHUTDOWN
        with pytest.raises(OSError) as e:
            h.recv(timeout=1)
        assert e.value.errno == errno.EBADF
        lib.recv_error = errno.ENOBUFS
        with pytest.raises(OSError) as e:
            h.recv(timeout=1)
        assert e.value.errno == errno.ENOBUFS
    with ebpf.EBPFDivert("udp", flags=Flag.SEND_ONLY) as h, pytest.raises(OSError):
        h._recv_impl(1500, 0)


def test_recv_batch(lib):
    with ebpf.EBPFDivert("udp") as h:
        for _ in range(3):
            lib.push(UDP_PACKET)
        assert len(h.recv_batch(count=5, timeout=1)) == 3


def test_send_round_trip_keeps_address(lib):
    with ebpf.EBPFDivert("udp") as h:
        lib.push(UDP_PACKET, outbound=0, ifidx=9)
        p = h.recv(timeout=1)
        assert h.send(p, recalculate_checksum=False) == len(UDP_PACKET)
        raw, outbound, ifidx, opaque = lib.sent[0]
        assert raw == UDP_PACKET
        assert (outbound, ifidx, opaque) == (0, 9, 0xDEADBEEF)
        assert lib.checksummed == 0
        h.send(p)
        # Packet uses libebpfdivert's checksum helper on Linux (WinDivert's on Windows).
        assert lib.checksummed == (0 if os.name == "nt" else 1)
        assert h.send_batch([p, p]) == 2
    with ebpf.EBPFDivert("udp", flags=Flag.RECV_ONLY) as h, pytest.raises(OSError):
        h._send_impl(Packet(UDP_PACKET))


def test_params_stats_shutdown(lib):
    with ebpf.EBPFDivert("udp") as h:
        assert h.get_param(Param.QUEUE_LEN) == 4096
        h.set_param(Param.QUEUE_LEN, 64)
        assert h.get_param(Param.QUEUE_LEN) == 64
        with pytest.raises(OSError):
            h.set_param(Param.QUEUE_LEN, 0)
        stats = h.stats()
        assert stats["diverted"] == 1 and stats["too_big"] == 7 and stats["queue_len"] == 64
        h.shutdown(ebpf.SHUTDOWN_RECV)
        assert lib.shutdowns == [ebpf.SHUTDOWN_RECV]
    with pytest.raises(RuntimeError):
        h.get_param(Param.QUEUE_LEN)


async_only_posix = pytest.mark.skipif(sys.platform == "win32", reason="add_reader needs a selector event loop")


@async_only_posix
async def test_recv_async_waits_for_event_fd(lib):
    with ebpf.EBPFDivert("udp") as h:
        loop = asyncio.get_running_loop()
        loop.call_later(0.05, lib.push, UDP_PACKET)
        p = await h.recv_async(timeout=2)
        assert p.dst_port == 12345
        with pytest.raises(TimeoutError):
            await h.recv_async(timeout=0.05)
        # Several concurrent waiters on one handle.
        loop.call_later(0.05, lib.push, UDP_PACKET)
        loop.call_later(0.1, lib.push, UDP_PACKET)
        got = await asyncio.gather(h.recv_async(timeout=2), h.recv_async(timeout=2))
        assert len(got) == 2
        lib.push(UDP_PACKET)
        lib.push(UDP_PACKET)
        assert len(await h.recv_batch_async(count=4, timeout=1)) == 2


@async_only_posix
async def test_recv_async_close_wakes_waiter(lib):
    h = ebpf.EBPFDivert("udp").open()
    task = asyncio.ensure_future(h.recv_async())
    await asyncio.sleep(0.05)
    h.close()
    with pytest.raises(OSError) as e:
        await task
    assert e.value.errno == errno.EBADF


async def test_send_async(lib):
    with ebpf.EBPFDivert("udp") as h:
        p = Packet(UDP_PACKET)
        assert await h.send_async(p) == len(UDP_PACKET)
        assert await h.send_batch_async([p]) == 1
