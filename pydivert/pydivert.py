# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys

from pydivert.base import BaseDivert
from pydivert.consts import Flag, Layer
from pydivert.packet import Packet


class PyDivert(BaseDivert):
    """
    A cross-platform facade for capturing, filtering, and modifying network packets.

    `PyDivert` provides a unified interface for WinDivert operations across multiple
    operating systems by delegating to OS-specific implementations:

    - **Windows:** Delegates to `pydivert.windivert.WinDivert`.
    - **Linux:** Delegates to `pydivert.linux.NetFilterQueue`.
    - **FreeBSD/macOS:** Delegates to `pydivert.bsd.Divert`.

    Use it as a context manager to ensure handles and firewall rules are properly cleaned up:

    ```python
    import pydivert

    # Divert all inbound TCP traffic on port 80
    with pydivert.PyDivert("tcp.DstPort == 80 and inbound") as w:
        for packet in w:
            print(f"Intercepted: {packet}")
            # Modify or just forward
            w.send(packet)
    ```

    The `PyDivert` class implements the `BaseDivert` interface. Most methods are
    common across platforms, but some advanced WinDivert features (like `Layer.FLOW`
    or `recv_ex`) are only available on Windows. On non-Windows platforms,
    accessing these features through `PyDivert` will raise `AttributeError`.

    .. note::
       Most implementations require administrator or root privileges to function.
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
            from pydivert.linux import NetFilterQueue

            return NetFilterQueue
        if sys.platform == "darwin":
            from pydivert.macos import MacOSDivert

            return MacOSDivert
        if sys.platform.startswith("freebsd"):
            from pydivert.bsd import Divert

            return Divert
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

    def __getattr__(self, name: str):
        # Delegate any other attributes to the implementation (e.g. WinDivert specific static methods)
        return getattr(self._impl, name)
