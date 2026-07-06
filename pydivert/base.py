# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of either:
#
# 1) The GNU Lesser General Public License as published by the Free
#    Software Foundation, either version 3 of the License, or (at your
#    option) any later version.
#
# 2) The GNU General Public License as published by the Free Software
#    Foundation, either version 2 of the License, or (at your option)
#    any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License and the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# and the GNU General Public License along with this program.  If not,
# see <https://www.gnu.org/licenses/>.

import abc
import errno
import logging
from typing import Any, TypeVar

from pydivert.consts import DEFAULT_PACKET_BUFFER_SIZE, Flag, Layer
from pydivert.packet import Packet

logger = logging.getLogger(__name__)


class FilterString(str):
    """
    A string subclass representing the filter string that is also callable
    to support user-space JIT filtering of packets.
    """

    _instance: Any

    def __call__(self, *, proto=None, src_addr=None, dst_addr=None, src_port=None, dst_port=None, direction=None):  # noqa: C901
        """
        Yields only packets matching the given criteria (user-space JIT filter).
        """
        for packet in self._instance:
            if proto:
                pkt_proto = packet.protocol[0]
                if pkt_proto is not None:
                    if hasattr(pkt_proto, "value"):
                        pkt_proto = pkt_proto.value
                    if pkt_proto != proto:
                        continue
                else:
                    continue
            if src_addr and packet.src_addr != src_addr:
                continue
            if dst_addr and packet.dst_addr != dst_addr:
                continue
            if src_port and packet.src_port != src_port:
                continue
            if dst_port and packet.dst_port != dst_port:
                continue
            if direction and packet.direction.name.lower() != direction.lower():
                continue
            yield packet


T = TypeVar("T", bound="BaseDivert")


class BaseDivert(abc.ABC):
    """
    Abstract base class for Divert implementations.
    """

    def __init__(
        self,
        filter: str = "true",
        layer: Layer = Layer.NETWORK,
        priority: int = 0,
        flags: Flag = Flag.DEFAULT,
        **kwargs,
    ) -> None:
        if isinstance(filter, str):
            filter = filter.strip()
        self._filter: str = str(filter)
        self._layer: Layer = layer
        self._priority: int = priority
        self._flags: Flag = flags
        self._is_open: bool = False
        self._jit_filter: Any | None = None

    @staticmethod
    @abc.abstractmethod
    def register() -> None:
        """Register the service (if applicable)."""
        pass  # pragma: no cover

    @staticmethod
    @abc.abstractmethod
    def is_registered() -> bool:
        """Check if the service is registered."""
        return True  # pragma: no cover

    @staticmethod
    @abc.abstractmethod
    def unregister() -> None:
        """Unregister the service (if applicable)."""
        pass  # pragma: no cover

    @staticmethod
    @abc.abstractmethod
    def check_filter(filter: str, layer: Layer = Layer.NETWORK) -> tuple[bool, int, str]:
        """Check if a filter is valid."""
        return True, 0, ""  # pragma: no cover

    @property
    def filter(self) -> FilterString:
        """The filter string."""
        s = FilterString(self._filter)
        s._instance = self
        return s

    @filter.setter
    def filter(self, value: str):
        self._filter = value

    @property
    def layer(self) -> Layer:
        """The layer."""
        return self._layer

    @layer.setter
    def layer(self, value: Layer):
        self._layer = value

    @property
    def priority(self) -> int:
        """The priority."""
        return self._priority

    @priority.setter
    def priority(self, value: int):
        self._priority = value

    @property
    def flags(self) -> Flag:
        """The flags."""
        return self._flags

    @flags.setter
    def flags(self, value: Flag):
        self._flags = value

    @property
    def is_open(self) -> bool:
        """True if the handle is open."""
        return self._is_open

    def open(self: T) -> T:
        """
        Opens the connection to the Divert subsystem.
        """
        if self._is_open:
            raise RuntimeError("Divert handle is already open.")

        self._open_impl()
        self._is_open = True
        logger.info(
            "Divert handle opened (filter=%r, layer=%s, priority=%d, flags=%s)",
            self.filter,
            self.layer,
            self.priority,
            self.flags,
        )
        return self

    def close(self) -> None:
        """
        Closes the connection to the Divert subsystem and cleans up resources.
        """
        if not self._is_open:
            raise RuntimeError("Divert handle is not open")
        self._close_impl()
        self._is_open = False
        logger.info("Divert handle closed.")

    def __del__(self) -> None:
        if getattr(self, "_is_open", False):
            import warnings

            warnings.warn(
                f"Unclosed {self.__class__.__name__} handle. Please use context manager or call close() explicitly.",
                ResourceWarning,
                stacklevel=1,
            )
            try:
                self.close()
            except Exception:
                pass

    def __enter__(self: T) -> T:
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._is_open:
            self.close()

    async def __aenter__(self: T) -> T:
        return self.open()

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._is_open:
            self.close()

    def __repr__(self) -> str:
        status = "open" if self.is_open else "closed"
        return (
            f'<{self.__class__.__name__} state="{status}" filter={self.filter!r} '
            f'layer="{self.layer}" priority="{self.priority}" flags="{self.flags}" />'
        )

    def recv(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        """
        Receives an intercepted packet that matched the filter.
        """
        if not self._is_open:
            raise RuntimeError("Divert handle is not open")

        if Flag.SEND_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is send-only")

        while True:
            packet = self._recv_impl(bufsize, timeout)
            if self._jit_filter is None or self._jit_filter(packet):
                logger.debug("Packet captured: %s", packet)
                return packet
            logger.debug("Packet dropped by JIT filter: %s", packet)

    def recv_batch(
        self,
        count: int = 1,
        bufsize: int = DEFAULT_PACKET_BUFFER_SIZE,
        timeout: float | None = None,
    ) -> list[Packet]:
        """
        Receives a batch of intercepted packets.
        """
        if not self._is_open:
            raise RuntimeError("Divert handle is not open")

        if Flag.SEND_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is send-only")

        packets = self._recv_batch_impl(count, bufsize, timeout)
        if self._jit_filter:
            filtered = [p for p in packets if self._jit_filter(p)]
            logger.debug("Batch captured: %d received, %d passed JIT", len(packets), len(filtered))
            return filtered
        logger.debug("Batch captured: %d received", len(packets))
        return packets

    def __iter__(self):
        while True:
            try:
                yield self.recv()
            except (EOFError, StopIteration, KeyboardInterrupt):
                break

    def __aiter__(self):
        return self

    async def __anext__(self) -> Packet:
        try:
            return await self.recv_async()
        except (EOFError, StopIteration, KeyboardInterrupt):
            raise StopAsyncIteration() from None  # pragma: no cover

    async def recv_async(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        """
        Asynchronous version of recv().
        """
        if not self._is_open:
            raise RuntimeError("Divert handle is not open")

        if Flag.SEND_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is send-only")

        while True:
            packet = await self._recv_async_impl(bufsize, timeout)
            if self._jit_filter is None or self._jit_filter(packet):
                logger.debug("Packet captured (async): %s", packet)
                return packet
            logger.debug("Packet dropped by JIT filter (async): %s", packet)

    async def recv_batch_async(
        self,
        count: int = 1,
        bufsize: int = DEFAULT_PACKET_BUFFER_SIZE,
        timeout: float | None = None,
    ) -> list[Packet]:
        """
        Asynchronously receives a batch of packets.
        """
        if not self._is_open:
            raise RuntimeError("Divert handle is not open")  # pragma: no cover

        if Flag.SEND_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is send-only")

        packets = await self._recv_batch_async_impl(count, bufsize, timeout)
        if self._jit_filter:
            filtered = [p for p in packets if self._jit_filter(p)]
            logger.debug("Batch captured (async): %d received, %d passed JIT", len(packets), len(filtered))
            return filtered
        logger.debug("Batch captured (async): %d received", len(packets))
        return packets

    def stats(self) -> dict[str, int]:
        """
        Returns a dictionary of handle statistics.
        """
        if not self._is_open:
            raise RuntimeError("Divert handle is not open")
        return self._stats_impl()

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """
        Injects a packet into the network stack.
        """
        if not self._is_open:
            raise RuntimeError("Divert handle is not open")

        if Flag.RECV_ONLY in self.flags:
            raise OSError(errno.EACCES, "Handle is recv-only")

        sent_len = self._send_impl(packet, recalculate_checksum)
        logger.debug("Packet injected: %d bytes", sent_len)
        return sent_len

    def send_batch(self, packets: list[Packet], recalculate_checksum: bool = True) -> int:
        """
        Injects a batch of packets into the network stack.
        """
        if not self._is_open:
            raise RuntimeError("Divert handle is not open")

        if Flag.RECV_ONLY in self.flags:
            raise OSError(errno.EACCES, "Handle is recv-only")

        count = self._send_batch_impl(packets, recalculate_checksum)
        logger.debug("Batch injected: %d packets", count)
        return count

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """
        Asynchronous version of send().
        """
        if not self._is_open:
            raise RuntimeError("Divert handle is not open")  # pragma: no cover

        if Flag.RECV_ONLY in self.flags:
            raise OSError(errno.EACCES, "Handle is recv-only")

        sent_len = await self._send_async_impl(packet, recalculate_checksum)
        logger.debug("Packet injected (async): %d bytes", sent_len)
        return sent_len

    async def send_batch_async(self, packets: list[Packet], recalculate_checksum: bool = True) -> int:
        """
        Asynchronously injects a batch of packets.
        """
        if not self._is_open:
            raise RuntimeError("Divert handle is not open")  # pragma: no cover

        if Flag.RECV_ONLY in self.flags:
            raise OSError(errno.EACCES, "Handle is recv-only")

        count = await self._send_batch_async_impl(packets, recalculate_checksum)  # pragma: no cover
        logger.debug("Batch injected (async): %d packets", count)  # pragma: no cover
        return count  # pragma: no cover

    @abc.abstractmethod
    def _open_impl(self) -> None:
        pass  # pragma: no cover

    @abc.abstractmethod
    def _close_impl(self) -> None:
        pass  # pragma: no cover

    @abc.abstractmethod
    def _recv_impl(self, bufsize: int, timeout: float | None) -> Packet:
        pass  # pragma: no cover

    @abc.abstractmethod
    def _recv_batch_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        pass  # pragma: no cover

    @abc.abstractmethod
    async def _recv_async_impl(self, bufsize: int, timeout: float | None) -> Packet:
        pass  # pragma: no cover

    @abc.abstractmethod
    async def _recv_batch_async_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        pass  # pragma: no cover

    @abc.abstractmethod
    def _send_impl(self, packet: Packet, recalculate_checksum: bool) -> int:
        pass  # pragma: no cover

    @abc.abstractmethod
    def _send_batch_impl(self, packets: list[Packet], recalculate_checksum: bool) -> int:
        pass  # pragma: no cover

    @abc.abstractmethod
    async def _send_async_impl(self, packet: Packet, recalculate_checksum: bool) -> int:
        pass  # pragma: no cover

    @abc.abstractmethod
    async def _send_batch_async_impl(self, packets: list[Packet], recalculate_checksum: bool) -> int:
        pass  # pragma: no cover

    @abc.abstractmethod
    def _stats_impl(self) -> dict[str, int]:
        pass  # pragma: no cover
