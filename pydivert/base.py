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
import asyncio
import logging
import socket
import errno
from typing import Any, Optional, TypeVar

from pydivert.consts import DEFAULT_PACKET_BUFFER_SIZE, Flag, Layer
from pydivert.packet import Packet

logger = logging.getLogger(__name__)

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
        self._jit_filter: Optional[Any] = None

    @staticmethod
    def register() -> None:
        """Register the service (if applicable)."""
        pass

    @staticmethod
    def is_registered() -> bool:
        """Check if the service is registered."""
        return True

    @staticmethod
    def unregister() -> None:
        """Unregister the service (if applicable)."""
        pass

    @staticmethod
    def check_filter(filter: str, layer: Layer = Layer.NETWORK) -> tuple[bool, int, str]:
        """Check if a filter is valid."""
        return True, 0, ""

    @property
    def filter(self) -> str:
        """The filter string."""
        return self._filter

    @property
    def layer(self) -> Layer:
        """The layer."""
        return self._layer

    @property
    def priority(self) -> int:
        """The priority."""
        return self._priority

    @property
    def flags(self) -> Flag:
        """The flags."""
        return self._flags

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
        logger.info("Divert handle opened (filter=%r, layer=%s, priority=%d, flags=%s)", 
                    self.filter, self.layer, self.priority, self.flags)
        return self

    def close(self) -> None:
        """
        Closes the connection to the Divert subsystem and cleans up resources.
        """
        if not self._is_open:
            raise RuntimeError("WinDivert handle is not open")
        self._close_impl()
        self._is_open = False
        logger.info("Divert handle closed.")

    def __enter__(self: T) -> T:
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.is_open:
            self.close()

    async def __aenter__(self: T) -> T:
        return self.open()

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.is_open:
            self.close()

    def __repr__(self) -> str:
        status = "open" if self.is_open else "closed"
        return f'<{self.__class__.__name__} state="{status}" filter={self.filter!r} layer="{self.layer}" priority="{self.priority}" flags="{self.flags}" />'

    def recv(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: Optional[float] = None) -> Packet:
        """
        Receives an intercepted packet that matched the filter.
        """
        if not self._is_open:
            raise RuntimeError("WinDivert handle is not open")
        
        if Flag.SEND_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is send-only")
        
        while True:
            packet = self._recv_impl(bufsize, timeout)
            if self._jit_filter is None or self._jit_filter(packet):
                logger.debug("Packet captured: %s", packet)
                return packet
            logger.debug("Packet dropped by JIT filter: %s", packet)

    def recv_batch(self, count: int = 1, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: Optional[float] = None) -> list[Packet]:
        """
        Receives a batch of intercepted packets.
        """
        if not self._is_open:
            raise RuntimeError("WinDivert handle is not open")

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
            raise StopAsyncIteration()

    async def recv_async(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: Optional[float] = None) -> Packet:
        """
        Asynchronous version of recv().
        """
        if not self._is_open:
            raise RuntimeError("WinDivert handle is not open")
        
        if Flag.SEND_ONLY in self.flags:
            raise OSError(errno.EBADF, "Handle is send-only")

        while True:
            packet = await self._recv_async_impl(bufsize, timeout)
            if self._jit_filter is None or self._jit_filter(packet):
                logger.debug("Packet captured (async): %s", packet)
                return packet
            logger.debug("Packet dropped by JIT filter (async): %s", packet)

    async def recv_batch_async(self, count: int = 1, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: Optional[float] = None) -> list[Packet]:
        """
        Asynchronously receives a batch of packets.
        """
        if not self._is_open:
            raise RuntimeError("WinDivert handle is not open")
        
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
            raise RuntimeError("WinDivert handle is not open")
        return self._stats_impl()

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """
        Injects a packet into the network stack.
        """
        if not self._is_open:
            raise RuntimeError("WinDivert handle is not open")

        if Flag.RECV_ONLY in self.flags:
            raise OSError(errno.EACCES, "Handle is recv-only")
        
        sent_len = self._send_impl(packet, recalculate_checksum)
        logger.debug("Packet injected: %d bytes", sent_len)
        return sent_len

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """
        Asynchronous version of send().
        """
        if not self._is_open:
            raise RuntimeError("WinDivert handle is not open")

        if Flag.RECV_ONLY in self.flags:
            raise OSError(errno.EACCES, "Handle is recv-only")

        sent_len = await self._send_async_impl(packet, recalculate_checksum)
        logger.debug("Packet injected (async): %d bytes", sent_len)
        return sent_len

    @abc.abstractmethod
    def _open_impl(self) -> None:
        pass

    @abc.abstractmethod
    def _close_impl(self) -> None:
        pass

    @abc.abstractmethod
    def _recv_impl(self, bufsize: int, timeout: float | None) -> Packet:
        pass

    @abc.abstractmethod
    def _recv_batch_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        pass

    @abc.abstractmethod
    async def _recv_async_impl(self, bufsize: int, timeout: float | None) -> Packet:
        pass

    @abc.abstractmethod
    async def _recv_batch_async_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        pass

    @abc.abstractmethod
    def _send_impl(self, packet: Packet, recalculate_checksum: bool) -> int:
        pass

    @abc.abstractmethod
    async def _send_async_impl(self, packet: Packet, recalculate_checksum: bool) -> int:
        pass

    @abc.abstractmethod
    def _stats_impl(self) -> dict[str, int]:
        pass
