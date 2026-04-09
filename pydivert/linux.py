# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import logging
from pydivert.base import BaseDivert
from pydivert.packet import Packet
from pydivert.consts import Layer, Flag

logger = logging.getLogger(__name__)

class NetFilterQueue(BaseDivert):
    """
    Linux implementation using NetFilterQueue.
    """
    def __init__(self, filter: str = "true", layer: Layer = Layer.NETWORK, priority: int = 0, flags: Flag = Flag.DEFAULT) -> None:
        super().__init__(filter, layer, priority, flags)
        self._nfqueue = None
        # TODO: Implement transpilation of WinDivert filter to BPF or similar
        self._translated_filter = filter

    def open(self) -> None:
        logger.info("Opening NetFilterQueue with filter: %s", self._translated_filter)
        # TODO: Setup NetFilterQueue
        pass

    def close(self) -> None:
        logger.info("Closing NetFilterQueue")
        # TODO: Close NetFilterQueue
        pass

    @property
    def is_open(self) -> bool:
        return self._nfqueue is not None

    def recv(self) -> Packet:
        # TODO: Implement recv using NetFilterQueue
        raise NotImplementedError("Linux support not yet fully implemented.")

    async def recv_async(self) -> Packet:
        # TODO: Implement async recv
        raise NotImplementedError("Linux support not yet fully implemented.")

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        # TODO: Implement send using NetFilterQueue
        raise NotImplementedError("Linux support not yet fully implemented.")

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        # TODO: Implement async send
        raise NotImplementedError("Linux support not yet fully implemented.")
