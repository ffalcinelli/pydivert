# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import abc
from collections.abc import AsyncIterator, Iterator
from typing import Any, TypeVar

from pydivert.consts import DEFAULT_PACKET_BUFFER_SIZE, Flag, Layer
from pydivert.packet import Packet

T = TypeVar("T", bound="BaseDivert")


class BaseDivert(abc.ABC):
    """
    Abstract base class for packet diversion implementations.

    This interface defines the core functionality for capturing, filtering,
    and re-injecting network packets. It is implemented by OS-specific backends:
    - `WinDivert` (Windows)
    - `eBPF` (Linux)

    For standard cross-platform usage, use the `pydivert.Divert` facade instead
    of instantiating these backends directly.
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
        self._filter: bytes | str = filter.encode() if isinstance(filter, str) else filter
        self._layer = layer
        self._priority = priority
        self._flags = flags
        self._handle: Any = None

    @staticmethod
    def register() -> None:
        """Register the service (if applicable)."""
        raise NotImplementedError()

    @staticmethod
    def is_registered() -> bool:
        """Check if the service is registered."""
        return True

    @staticmethod
    def unregister() -> None:
        """Unregister the service (if applicable)."""
        raise NotImplementedError()

    @staticmethod
    def check_filter(filter: str, layer: Layer = Layer.NETWORK) -> tuple[bool, int, str]:
        """Check if the given packet filter string is valid."""
        return True, 0, ""

    def __repr__(self) -> str:
        state = "open" if self.is_open else "closed"
        filter_str = self.filter
        return (
            f'<{self.__class__.__name__} state="{state}" filter="{filter_str}" layer="{self._layer}" '
            f'priority="{self._priority}" flags="{self._flags}" />'
        )

    @property
    def filter(self) -> str:
        """Returns the packet filter string."""
        return self._filter.decode() if isinstance(self._filter, bytes) else str(self._filter)

    @property
    def layer(self) -> Layer:
        """Returns the WinDivert layer."""
        return self._layer  # pragma: no cover

    @property
    def priority(self) -> int:
        """Returns the handle priority."""
        return self._priority  # pragma: no cover

    @property
    def flags(self) -> Flag:
        """Returns the WinDivert flags."""
        return self._flags  # pragma: no cover

    @abc.abstractmethod
    def open(self) -> None:
        """
        Opens a connection to the Divert subsystem (WinDivert, NFQUEUE, or Divert socket).
        Matches packets according to the `filter` provided at initialization.

        :raises RuntimeError: If the handle is already open.
        :raises OSError: If the connection fails (e.g. insufficient permissions).
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def close(self) -> None:
        """
        Closes the connection to the Divert subsystem and cleans up any
        firewall rules or resources.
        """
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def is_open(self) -> bool:
        """Indicates if the Divert handle is currently open."""
        raise NotImplementedError()

    @abc.abstractmethod
    def recv(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        """
        Receives an intercepted packet that matched the filter.
        This method blocks until a packet is available or the timeout is reached.

        :param bufsize: The maximum size of the packet to receive.
        :param timeout: Maximum time to wait for a packet (in seconds).
        :return: A `pydivert.Packet` instance.
        :raises RuntimeError: If the handle is closed.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    async def recv_async(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        """
        Asynchronous version of `recv()`.
        Yields control while waiting for a packet.

        :param bufsize: The maximum size of the packet to receive.
        :param timeout: Maximum time to wait for a packet (in seconds/milliseconds depending on backend).
        :return: A `pydivert.Packet` instance.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """
        Injects a packet into the network stack or accepts a modified intercepted packet.

        :param packet: The `pydivert.Packet` to send.
        :param recalculate_checksum: If `True`, recalculate IP, TCP, UDP, and ICMP checksums before sending.
        :return: Number of bytes sent.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """
        Asynchronous version of `send()`.

        :param packet: The `pydivert.Packet` to send.
        :param recalculate_checksum: If `True`, recalculate checksums.
        :return: Number of bytes sent.
        """
        raise NotImplementedError()

    def __enter__(self: T) -> T:
        self.open()
        return self  # pragma: no cover

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()  # pragma: no cover

    async def __aenter__(self: T) -> T:
        self.open()
        return self  # pragma: no cover

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()  # pragma: no cover

    def __iter__(self) -> Iterator[Packet]:
        return self  # pragma: no cover

    def __next__(self) -> Packet:
        return self.recv()  # pragma: no cover

    def __aiter__(self) -> AsyncIterator[Packet]:
        return self  # pragma: no cover

    async def __anext__(self) -> Packet:
        return await self.recv_async()  # pragma: no cover
