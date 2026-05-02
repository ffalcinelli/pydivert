# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys
from typing import Any

from pydivert.base import BaseDivert
from pydivert.consts import DEFAULT_PACKET_BUFFER_SIZE, Flag, Layer
from pydivert.packet import Packet


class Divert(BaseDivert):
    """
    A unified, cross-platform facade for capturing, filtering, and modifying network packets.
    """
    
    # Re-expose members for documentation since BaseDivert is internal
    recv = BaseDivert.recv
    recv_async = BaseDivert.recv_async
    recv_batch = BaseDivert.recv_batch
    recv_batch_async = BaseDivert.recv_batch_async
    send = BaseDivert.send
    send_async = BaseDivert.send_async
    stats = BaseDivert.stats
    filter = BaseDivert.filter
    layer = BaseDivert.layer
    priority = BaseDivert.priority
    flags = BaseDivert.flags
    open = BaseDivert.open
    close = BaseDivert.close

    def __init__(
        self,
        filter: str = "true",
        layer: Layer = Layer.NETWORK,
        priority: int = 0,
        flags: Flag = Flag.DEFAULT,
    ) -> None:
        super().__init__(filter, layer, priority, flags)
        impl_class = self._get_implementation_class()
        self._impl: BaseDivert = impl_class(filter, layer, priority, flags)

    @staticmethod
    def _get_implementation_class() -> type[BaseDivert]:
        if sys.platform == "win32":
            from pydivert.windivert import WinDivert
            return WinDivert
        if sys.platform.startswith("linux"):
            from pydivert.ebpf import EBPFDivert
            return EBPFDivert

        raise NotImplementedError(f"Unsupported platform: {sys.platform}. Divert only supports Windows and Linux.")

    @classmethod
    def register_service(cls) -> None:
        cls._get_implementation_class().register()

    @classmethod
    def is_registered(cls) -> bool:
        return cls._get_implementation_class().is_registered()

    @classmethod
    def unregister(cls) -> None:
        cls._get_implementation_class().unregister()

    @classmethod
    def check_filter(cls, filter: str, layer: Layer = Layer.NETWORK) -> tuple[bool, int, str]:
        return cls._get_implementation_class().check_filter(filter, layer)

    def _open_impl(self) -> None:
        self._impl.open()

    def _close_impl(self) -> None:
        self._impl.close()

    def _recv_impl(self, bufsize: int, timeout: float | None) -> Packet:
        return self._impl._recv_impl(bufsize, timeout)

    def _recv_batch_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        return self._impl._recv_batch_impl(count, bufsize, timeout)

    async def _recv_async_impl(self, bufsize: int, timeout: float | None) -> Packet:
        return await self._impl._recv_async_impl(bufsize, timeout)

    async def _recv_batch_async_impl(self, count: int, bufsize: int, timeout: float | None) -> list[Packet]:
        return await self._impl._recv_batch_async_impl(count, bufsize, timeout)

    def _send_impl(self, packet: Packet, recalculate_checksum: bool) -> int:
        return self._impl._send_impl(packet, recalculate_checksum)

    async def _send_async_impl(self, packet: Packet, recalculate_checksum: bool) -> int:
        return await self._impl._send_async_impl(packet, recalculate_checksum)

    def _stats_impl(self) -> dict[str, int]:
        return self._impl._stats_impl()

    @property
    def is_open(self) -> bool:
        # Override BaseDivert.is_open to check the underlying implementation
        return self._impl.is_open

    def __getattr__(self, name: str):
        return getattr(self._impl, name)

    def __dir__(self) -> list[str]:
        return sorted(set(super().__dir__()) | set(dir(self._impl)))
