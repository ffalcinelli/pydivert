# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import abc
import socket
import time
from collections.abc import AsyncIterator, Iterator
from typing import Any, TypeVar

from pydivert.consts import DEFAULT_PACKET_BUFFER_SIZE, Flag, Layer
from pydivert.packet import Packet

T = TypeVar("T", bound="BaseDivert")


class BaseDivert(abc.ABC):
    """
    Abstract base class for packet diversion implementations.

    This class manages shared state and provides the public API for packet
    interception, delegating low-level operations to backend-specific methods.
    """

    def __init__(
        self,
        filter: str = "true",
        layer: Layer = Layer.NETWORK,
        priority: int = 0,
        flags: Flag = Flag.DEFAULT,
    ) -> None:
        if isinstance(filter, str):
            filter = filter.strip()
        self._filter: str = str(filter)
        self._layer = layer
        self._priority = priority
        self._flags = flags
        self._is_open = False
        self._jit_filter = None

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
        """Check if the given packet filter string is valid."""
        return True, 0, ""

    def __repr__(self) -> str:
        state = "open" if self.is_open else "closed"
        return (
            f'<{self.__class__.__name__} state="{state}" filter="{self.filter}" layer="{self._layer}" '
            f'priority="{self._priority}" flags="{self._flags}" />'
        )

    @property
    def filter(self) -> str:
        """Returns the packet filter string."""
        return self._filter

    @property
    def layer(self) -> Layer:
        """Returns the WinDivert layer."""
        return self._layer

    @property
    def priority(self) -> int:
        """Returns the handle priority."""
        return self._priority

    @property
    def flags(self) -> Flag:
        """Returns the WinDivert flags."""
        return self._flags

    @property
    def is_open(self) -> bool:
        """Indicates if the Divert handle is currently open."""
        return self._is_open

    def _compile_jit_if_needed(self):
        # We always compile a JIT filter for complex expressions as a fallback
        from pydivert.filter import transpile_to_python
        from pydivert.jit import compile_filter
        expr = transpile_to_python(self._filter)
        self._jit_filter = compile_filter(expr)

    def open(self) -> None:
        """
        Opens a connection to the Divert subsystem.
        """
        if self._is_open:
            raise RuntimeError(f"{self.__class__.__name__} handle is already open.")
        self._open_impl()
        self._compile_jit_if_needed()
        self._is_open = True

    def close(self) -> None:
        """
        Closes the connection to the Divert subsystem and cleans up resources.
        """
        if not self._is_open:
            raise RuntimeError(f"{self.__class__.__name__} handle is not open.")
        self._close_impl()
        self._is_open = False

    def recv(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        """
        Receives an intercepted packet that matched the filter.
        """
        if not self._is_open:
            raise RuntimeError(f"{self.__class__.__name__} handle is not open.")
        
        while True:
            packet = self._recv_impl(bufsize, timeout)
            if self._jit_filter is None or self._jit_filter(packet):
                return packet

    def recv_batch(self, count: int = 1, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> list[Packet]:
        """
        Receives a batch of intercepted packets.
        """
        if not self._is_open:
            raise RuntimeError(f"{self.__class__.__name__} handle is not open.")
        
        packets = self._recv_batch_impl(count, bufsize, timeout)
        if self._jit_filter:
            return [p for p in packets if self._jit_filter(p)]
        return packets

    async def recv_async(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        """
        Asynchronous version of recv().
        """
        if not self._is_open:
            raise RuntimeError(f"{self.__class__.__name__} handle is not open.")
        
        while True:
            packet = await self._recv_async_impl(bufsize, timeout)
            if self._jit_filter is None or self._jit_filter(packet):
                return packet

    async def recv_batch_async(self, count: int = 1, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> list[Packet]:
        """
        Asynchronously receives a batch of packets.
        """
        if not self._is_open:
            raise RuntimeError(f"{self.__class__.__name__} handle is not open.")
        
        packets = await self._recv_batch_async_impl(count, bufsize, timeout)
        if self._jit_filter:
            return [p for p in packets if self._jit_filter(p)]
        return packets

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """
        Injects a packet into the network stack.
        """
        if not self._is_open:
            raise RuntimeError(f"{self.__class__.__name__} handle is not open.")
        return self._send_impl(packet, recalculate_checksum)

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """
        Asynchronous version of send().
        """
        if not self._is_open:
            raise RuntimeError(f"{self.__class__.__name__} handle is not open.")
        return await self._send_async_impl(packet, recalculate_checksum)

    @abc.abstractmethod
    def _open_impl(self) -> None:
        """Backend-specific open logic."""
        pass

    @abc.abstractmethod
    def _close_impl(self) -> None:
        """Backend-specific close logic."""
        pass

    @abc.abstractmethod
    def _recv_impl(self, bufsize: int, timeout: float | None) -> Packet:
        """Backend-specific sync receive logic."""
        pass

    @abc.abstractmethod
    def _recv_batch_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        """Backend-specific sync batch receive logic."""
        pass

    @abc.abstractmethod
    async def _recv_async_impl(self, bufsize: int, timeout: float | None) -> Packet:
        """Backend-specific async receive logic."""
        pass

    @abc.abstractmethod
    async def _recv_batch_async_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        """Backend-specific async batch receive logic."""
        pass

    @abc.abstractmethod
    def _send_impl(self, packet: Packet, recalculate_checksum: bool) -> int:
        """Backend-specific sync send logic."""
        pass

    @abc.abstractmethod
    async def _send_async_impl(self, packet: Packet, recalculate_checksum: bool) -> int:
        """Backend-specific async send logic."""
        pass

    def __enter__(self: T) -> T:
        self.open()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    async def __aenter__(self: T) -> T:
        self.open()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def __iter__(self) -> Iterator[Packet]:
        return self

    def __next__(self) -> Packet:
        return self.recv()

    def __aiter__(self) -> AsyncIterator[Packet]:
        return self

    async def __anext__(self) -> Packet:
        return await self.recv_async()
