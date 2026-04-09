# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys
from pydivert.consts import Layer, Flag
from pydivert.packet import Packet
from pydivert.base import BaseDivert

class PyDivert(BaseDivert):
    """
    Abstract layer for Divert operations across different operating systems.
    """
    def __init__(self, filter: str = "true", layer: Layer = Layer.NETWORK, priority: int = 0, flags: Flag = Flag.DEFAULT) -> None:
        super().__init__(filter, layer, priority, flags)
        self._impl = self._get_implementation()(filter, layer, priority, flags)

    def _get_implementation(self):
        if sys.platform == "win32":
            from pydivert.windivert import WinDivert
            return WinDivert
        elif sys.platform.startswith("linux"):
            from pydivert.linux import NetFilterQueue
            return NetFilterQueue
        elif sys.platform.startswith("freebsd") or sys.platform == "darwin":
            from pydivert.bsd import Divert
            return Divert
        else:
            raise NotImplementedError(f"Unsupported platform: {sys.platform}")

    def open(self) -> None:
        self._impl.open()

    def close(self) -> None:
        self._impl.close()

    @property
    def is_open(self) -> bool:
        return self._impl.is_open

    def recv(self) -> Packet:
        return self._impl.recv()

    async def recv_async(self) -> Packet:
        return await self._impl.recv_async()

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        return self._impl.send(packet, recalculate_checksum)

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        return await self._impl.send_async(packet, recalculate_checksum)
