# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
"""
Linux backend: a thin ctypes shim over libebpfdivert.

libebpfdivert implements the WinDivert semantics on top of eBPF (TC hooks),
including the WinDivert filter language, re-injection, priorities and
queue parameters, and returns WINDIVERT_ADDRESS-compatible metadata.  This
class therefore mirrors :class:`pydivert.windivert.WinDivert`.
"""

import asyncio
import ctypes
import errno
import logging
from ctypes import byref, c_char, c_char_p, c_uint32, c_uint64

from .base import BaseDivert
from .bpf import STAT_NAMES, OpenOpts, WinDivertAddress, libebpfdivert, strerror
from .consts import DEFAULT_PACKET_BUFFER_SIZE, Flag, Layer, Param
from .packet import Packet

logger = logging.getLogger(__name__)

SHUTDOWN_RECV = 1
SHUTDOWN_SEND = 2
SHUTDOWN_BOTH = 3


def _lib():
    if libebpfdivert is None:
        raise ImportError(
            "libebpfdivert not found: reinstall pydivert or set PYDIVERT_EBPFDIVERT_LIB to the library path."
        )
    return libebpfdivert


def _raise(ret: int, what: str) -> None:
    err = -ret
    if err == errno.EAGAIN:
        raise TimeoutError("The read operation timed out")
    if err == errno.ESHUTDOWN:
        raise OSError(errno.EBADF, "Handle closed while receiving")
    raise OSError(err, f"{what}: {strerror(err)}")


class EBPFDivert(BaseDivert):
    """
    Linux implementation of the Divert interface, backed by libebpfdivert.
    """

    def __init__(
        self,
        filter: str = "true",
        layer: Layer = Layer.NETWORK,
        priority: int = 0,
        flags: Flag = Flag.DEFAULT,
        **kwargs,
    ) -> None:
        super().__init__(filter, layer, priority, flags, **kwargs)
        self._handle: int | None = None
        self._interfaces: list[str] | None = kwargs.get("interfaces")
        self._ring_bytes: int = int(kwargs.get("ring_bytes", 0))
        self._recv_buf: bytearray | None = None
        self._recv_buf_c = None
        self._waiters: list[asyncio.Future] = []
        self._reader_loop: asyncio.AbstractEventLoop | None = None
        self._event_fd: int | None = None

    @staticmethod
    def register() -> None:
        """Nothing to install on Linux; programs are attached per handle."""

    @staticmethod
    def is_registered() -> bool:
        return libebpfdivert is not None

    @staticmethod
    def unregister() -> None:
        """Detach programs left behind by processes that died without closing their handles."""
        if libebpfdivert is not None:
            libebpfdivert.ebpfdivert_unregister()

    @staticmethod
    def check_filter(filter: str, layer: Layer = Layer.NETWORK) -> tuple[bool, int, str]:
        msg, pos = c_char_p(), c_uint32(0)
        ret = _lib().ebpfdivert_helper_compile_filter(filter.encode(), int(layer), byref(msg), byref(pos))
        if ret == 0:
            return True, 0, ""
        return False, pos.value, msg.value.decode() if msg.value else strerror(ret)

    # -- lifecycle -----------------------------------------------------------

    def _open_impl(self) -> None:
        lib = _lib()
        opts = OpenOpts(sz=ctypes.sizeof(OpenOpts), ifnames=None, ring_bytes=self._ring_bytes)
        names = None
        if self._interfaces:
            names = (c_char_p * (len(self._interfaces) + 1))(*[n.encode() for n in self._interfaces], None)
            opts.ifnames = ctypes.cast(names, ctypes.POINTER(c_char_p))
        handle = lib.ebpfdivert_open(
            self.filter.encode(), int(self.layer), int(self.priority), int(self.flags), byref(opts)
        )
        if not handle:
            err = ctypes.get_errno() or errno.EIO
            if err == errno.EINVAL:
                ok, pos, msg = self.check_filter(self.filter, self.layer)
                if not ok:
                    # WinDivert reports a bad filter as ERROR_INVALID_PARAMETER.
                    raise OSError(errno.EINVAL, f"Invalid filter at position {pos}: {msg}")
            if err == errno.EOPNOTSUPP:
                if self.layer == Layer.SOCKET and Flag.SNIFF not in self.flags:
                    raise NotImplementedError(
                        "This SOCKET filter cannot be enforced on Linux: only BIND and CONNECT events can be "
                        "blocked, with filters on event, protocol, local/remote address and port, and "
                        "processId. Use Flag.SNIFF to only observe."
                    )
                raise NotImplementedError(f"Layer {Layer(self.layer).name} is not supported on this system.")
            raise OSError(err, f"ebpfdivert_open: {strerror(err)}")
        self._handle = handle
        self._event_fd = lib.ebpfdivert_get_event_fd(handle)

    def _close_impl(self) -> None:
        handle, self._handle = self._handle, None
        self._remove_reader()
        for fut in self._waiters:
            if not fut.done():
                fut.set_result(None)
        self._waiters.clear()
        if handle:
            _lib().ebpfdivert_close(handle)

    def shutdown(self, how: int = SHUTDOWN_BOTH) -> None:
        """Stop receiving (``SHUTDOWN_RECV``) and/or sending (``SHUTDOWN_SEND``), like WinDivertShutdown."""
        ret = _lib().ebpfdivert_shutdown(self._require_handle(), how)
        if ret < 0:
            _raise(ret, "ebpfdivert_shutdown")

    def _require_handle(self) -> int:
        if not self._handle:
            raise RuntimeError("Divert handle is not open")
        return self._handle

    # -- receive -------------------------------------------------------------

    def _buffer(self, bufsize: int):
        if self._recv_buf is None or len(self._recv_buf) != bufsize:
            self._recv_buf = bytearray(bufsize)
            self._recv_buf_c = (c_char * bufsize).from_buffer(self._recv_buf)
        return self._recv_buf, self._recv_buf_c

    def _recv_impl(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        if Flag.SEND_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is send-only")
        handle = self._require_handle()
        buf, buf_c = self._buffer(bufsize)
        addr = WinDivertAddress()
        recv_len = c_uint32(0)
        timeout_ms = -1 if timeout is None else max(0, int(timeout * 1000))
        ret = _lib().ebpfdivert_recv(handle, buf_c, bufsize, byref(recv_len), byref(addr), timeout_ms)
        if ret < 0:
            _raise(ret, "ebpfdivert_recv")
        return Packet(memoryview(buf)[: recv_len.value], wd_addr=addr)

    def _recv_batch_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        packets = [self._recv_impl(bufsize, timeout)]
        while len(packets) < count:
            try:
                packets.append(self._recv_impl(bufsize, 0))
            except TimeoutError:
                break
        return packets

    def _on_readable(self) -> None:
        waiters, self._waiters = self._waiters, []
        for fut in waiters:
            if not fut.done():
                fut.set_result(None)
        # The event fd is level-triggered: stop watching until someone waits.
        self._remove_reader()

    def _remove_reader(self) -> None:
        if self._reader_loop is not None and self._event_fd is not None:
            try:
                self._reader_loop.remove_reader(self._event_fd)
            except (ValueError, RuntimeError):  # pragma: no cover
                pass
        self._reader_loop = None

    async def _wait_readable(self, timeout: float | None) -> None:
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._waiters.append(fut)
        if self._reader_loop is None and self._event_fd is not None:
            loop.add_reader(self._event_fd, self._on_readable)
            self._reader_loop = loop
        try:
            await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            pass
        finally:
            if fut in self._waiters:
                self._waiters.remove(fut)
            if not self._waiters:
                self._remove_reader()

    async def _recv_async_impl(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        if Flag.SEND_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is send-only")
        loop = asyncio.get_running_loop()
        deadline = None if timeout is None else loop.time() + timeout
        while True:
            try:
                return self._recv_impl(bufsize, 0)
            except TimeoutError:
                pass
            remaining = None if deadline is None else deadline - loop.time()
            if remaining is not None and remaining <= 0:
                raise TimeoutError("The read operation timed out")
            await self._wait_readable(remaining)
            if not self._handle:
                raise OSError(errno.EBADF, "Handle closed while receiving")

    async def _recv_batch_async_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        packets = [await self._recv_async_impl(bufsize, timeout)]
        while len(packets) < count:
            try:
                packets.append(self._recv_impl(bufsize, 0))
            except TimeoutError:
                break
        return packets

    # -- send ----------------------------------------------------------------

    def _send_impl(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        if Flag.RECV_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is receive-only")
        handle = self._require_handle()
        if recalculate_checksum:
            packet.recalculate_checksums()
        raw = packet._raw
        buf = (c_char * len(raw)).from_buffer(raw)
        send_len = c_uint32(0)
        ret = _lib().ebpfdivert_send(handle, buf, len(raw), byref(send_len), byref(packet.wd_addr))
        if ret < 0:
            _raise(ret, "ebpfdivert_send")
        return send_len.value

    def _send_batch_impl(self, packets: list[Packet], recalculate_checksum: bool) -> int:
        count = 0
        for p in packets:
            try:
                if self._send_impl(p, recalculate_checksum) > 0:
                    count += 1
            except OSError as e:
                logger.debug("Failed to send packet in batch: %s", e)
        return count

    async def _send_async_impl(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        # Injection never blocks for long (raw/packet sockets): no thread hop needed.
        return self._send_impl(packet, recalculate_checksum)

    async def _send_batch_async_impl(self, packets: list[Packet], recalculate_checksum: bool) -> int:
        return self._send_batch_impl(packets, recalculate_checksum)

    # -- parameters and statistics -------------------------------------------

    def get_param(self, name: Param) -> int:
        value = c_uint64(0)
        ret = _lib().ebpfdivert_get_param(self._require_handle(), int(name), byref(value))
        if ret < 0:
            _raise(ret, "ebpfdivert_get_param")
        return value.value

    def set_param(self, name: Param, value: int) -> int:
        ret = _lib().ebpfdivert_set_param(self._require_handle(), int(name), value)
        if ret < 0:
            _raise(ret, "ebpfdivert_set_param")
        return 1

    def _stats_impl(self) -> dict[str, int]:
        stats = dict.fromkeys(STAT_NAMES, 0)
        if not self._handle:
            return stats
        values = (c_uint64 * len(STAT_NAMES))()
        n = _lib().ebpfdivert_get_handle_stats(self._handle, values, len(STAT_NAMES))
        for i in range(max(0, n)):
            stats[STAT_NAMES[i]] = values[i]
        stats["queue_len"] = self.get_param(Param.QUEUE_LEN)
        stats["queue_time"] = self.get_param(Param.QUEUE_TIME)
        stats["queue_size"] = self.get_param(Param.QUEUE_SIZE)
        return stats
