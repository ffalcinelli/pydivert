# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import abc
import asyncio
from typing import Any, AsyncIterator, Iterator
from pydivert.packet import Packet
from pydivert.consts import Layer, Flag

class BaseDivert(abc.ABC):
    """
    Abstract base class for Divert implementations.
    """

    def __init__(
        self, filter: str = "true", layer: Layer = Layer.NETWORK, priority: int = 0, flags: Flag = Flag.DEFAULT
    ) -> None:
        self.filter = filter
        self.layer = layer
        self.priority = priority
        self.flags = flags

    @abc.abstractmethod
    def open(self) -> None:
        """Opens the divert handle."""
        pass

    @abc.abstractmethod
    def close(self) -> None:
        """Closes the divert handle."""
        pass

    @property
    @abc.abstractmethod
    def is_open(self) -> bool:
        """Returns True if the handle is open."""
        pass

    @abc.abstractmethod
    def recv(self) -> Packet:
        """Receives a packet synchronously."""
        pass

    @abc.abstractmethod
    async def recv_async(self) -> Packet:
        """Receives a packet asynchronously."""
        pass

    @abc.abstractmethod
    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """Sends a packet synchronously."""
        pass

    @abc.abstractmethod
    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """Sends a packet asynchronously."""
        pass

    def __enter__(self) -> "BaseDivert":
        self.open()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    async def __aenter__(self) -> "BaseDivert":
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
