# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys

from pydivert.base import BaseDivert
from pydivert.consts import DEFAULT_PACKET_BUFFER_SIZE, Flag, Layer
from pydivert.packet import Packet


class PyDivert(BaseDivert):
    """
    A cross-platform facade for capturing, filtering, and modifying network packets.
    Routes to:
    - Windows: `pydivert.windivert.WinDivert`
    - Linux: `pydivert.ebpf.EBPFDivert`
    """

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

        raise NotImplementedError(f"Unsupported platform: {sys.platform}. PyDivert only supports Windows and Linux.")

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

    def open(self) -> None:
        self._impl.open()

    def close(self) -> None:
        self._impl.close()

    @property
    def is_open(self) -> bool:
        return self._impl.is_open

    def recv(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        return self._impl.recv(bufsize, timeout)

    async def recv_async(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        return await self._impl.recv_async(bufsize, timeout)

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        return self._impl.send(packet, recalculate_checksum)

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        return await self._impl.send_async(packet, recalculate_checksum)

    def __getattr__(self, name: str):
        return getattr(self._impl, name)

    def __dir__(self) -> list[str]:
        return sorted(set(super().__dir__()) | set(dir(self._impl)))
