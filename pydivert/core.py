# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys

from pydivert.base import BaseDivert
from pydivert.consts import DEFAULT_PACKET_BUFFER_SIZE, Flag, Layer
from pydivert.packet import Packet


class Divert(BaseDivert):
    """
    A unified, cross-platform facade for capturing, filtering, and modifying network packets.

    The `Divert` class provides a high-level API that abstracts the underlying OS-specific
    mechanisms for packet diversion. Depending on the host operating system, it routes
    operations to:

    1.  **Windows (10/11):** Uses the **WinDivert** driver and Windows Filtering Platform (WFP).
    2.  **Linux (Kernel 5.8+):** Uses **eBPF (CO-RE)** and the Traffic Control (TC) subsystem.

    This class handles the lifecycle of packet interception: from attaching kernel-mode hooks
    and compiling filter strings to safely reinjecting modified buffers back into the OS
    network stack. It ensures that application logic written for one platform is highly
    portable to the other, provided the underlying requirements (like eBPF support) are met.

    ### Lifecycle & OS Interaction:
    When a `Divert` instance is opened, it installs a hook in the kernel's network path.
    Packets matching the `filter` are **stolen** (taken out of the network stack).
    They will not reach their destination unless explicitly reinjected via :meth:`send`.

    - **On Windows**, the WinDivert driver intercepts packets at various WFP layers.
    - **On Linux**, an eBPF program is attached to the `clsact` qdisc of the specified
      interface (defaulting to 'lo' or all available if configured), effectively diverting
      packets from the TC ingress/egress paths.

    ### Performance Note:
    On Linux, `Divert` leverages a high-performance `BPF_MAP_TYPE_RINGBUF` to transfer
    packet data from the kernel to user-space with minimal overhead. On Windows, it utilizes
    the native WinDivert overlapped I/O capabilities.

    Attributes:
        filter (str): The WinDivert-style filter string used for capture.
        layer (Layer): The network layer at which capture occurs (e.g., NETWORK, FLOW).
        priority (int): The priority of the handle relative to other capture handles.
        flags (Flag): Behavioral flags (e.g., SNIFF, DROP, RECV_ONLY).
    """

    def __init__(
        self,
        filter: str = "true",
        layer: Layer = Layer.NETWORK,
        priority: int = 0,
        flags: Flag = Flag.DEFAULT,
    ) -> None:
        """
        Initializes a new Divert handle.

        The underlying backend is selected automatically based on `sys.platform`.

        ### Filter Language & Compilation:
        - **Windows:** The filter string is passed directly to the WinDivert driver,
          which compiles it into a WFP-compatible bytecode.
        - **Linux:** The filter is transpiled via the internal `Lark` parser into a set
          of rules stored in a BPF Map. The eBPF program iterates through these rules
          at the kernel level to decide which packets to steal.

        ### Privilege Requirements:
        - **Windows:** Requires **Administrator** privileges to communicate with
          the `WinDivert64.sys` driver.
        - **Linux:** Requires **root** or `CAP_BPF` + `CAP_NET_RAW` + `CAP_NET_ADMIN`
          capabilities to load BPF programs and attach TC hooks.

        Args:
            filter: A boolean expression determining which packets to capture.
                Supported keywords include `ip`, `tcp`, `udp`, `icmp`, `inbound`,
                `outbound`, and field comparisons (e.g., `tcp.DstPort == 80`).
            layer: The layer to capture from. `Layer.NETWORK` is standard.
                `Layer.FLOW` and `Layer.SOCKET` have varying levels of support
                on Linux.
            priority: Handle priority. Higher values are processed first.
            flags: Options to modify behavior. `Flag.SNIFF` allows monitoring
                without stealing the packet.

        Raises:
            PermissionError: If the process lacks the necessary OS privileges.
            ValueError: If the `filter` string contains syntax errors.
            NotImplementedError: If the platform is not Windows or Linux, or if
                unsupported filter keywords/layers are used on the current backend.
            ImportError: On Linux, if `libbpf` is not installed on the system.
        """
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
        """
        Installs and starts the WinDivert driver service on the host system.
        (Windows only).
        """
        cls._get_implementation_class().register()

    @classmethod
    def is_registered(cls) -> bool:
        """
        Checks if the network driver is correctly installed on the system.
        """
        return cls._get_implementation_class().is_registered()

    @classmethod
    def unregister(cls) -> None:
        """
        Stops and removes the WinDivert driver service (Windows only).
        """
        cls._get_implementation_class().unregister()

    @classmethod
    def check_filter(cls, filter: str, layer: Layer = Layer.NETWORK) -> tuple[bool, int, str]:
        """
        Validates the syntax of a filter string without opening a handle.
        """
        return cls._get_implementation_class().check_filter(filter, layer)

    def open(self) -> None:
        """
        Allocates system resources and attaches the capture hooks to the kernel.

        ### Internal Operations:
        - **Windows:** Calls `WinDivertOpen`, obtaining a kernel handle.
        - **Linux:** Loads the `pydivert.bpf.o` object, initializes the BPF ring buffer,
          and attaches the capture program to the network interface using `libbpf`.
          It also creates a raw socket for packet reinjection.

        Raises:
            RuntimeError: If the handle is already open.
            OSError: If the kernel driver fails to load, the interface cannot be found,
                or if the eBPF program fails verification (Linux).
        """
        self._impl.open()

    def close(self) -> None:
        """
        Detaches kernel hooks and releases all allocated resources.

        After calling `close`, the handle can no longer be used for capture or
        injection. Any packets currently buffered in the kernel that were not
        received by user-space may be dropped by the OS, depending on the backend.

        ### Cleanup:
        - **Windows:** Closes the handle via `WinDivertClose`.
        - **Linux:** Detaches TC ingress/egress programs, destroys the BPF ring buffer,
          and unloads the BPF object from the kernel.

        Raises:
            RuntimeError: If the handle is already closed.
        """
        self._impl.close()

    @property
    def is_open(self) -> bool:
        """Indicates if the Divert handle is currently open and attached."""
        return self._impl.is_open

    def recv(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        """
        Blocks until a packet matching the filter is intercepted.

        Intercepted packets are effectively "paused" in the kernel. The `recv` call
        transfers the raw packet data and its metadata (interface, direction, etc.)
        into a :class:`pydivert.Packet` object.

        ### Implementation Details:
        - **Windows:** Invokes `WinDivertRecv`. If `timeout` is provided, it uses
          overlapped I/O and `GetOverlappedResult`.
        - **Linux:** Polls the BPF ring buffer. If empty, it waits up to `timeout`
          seconds using `ring_buffer__poll`.

        Args:
            bufsize: Maximum number of bytes to read into the buffer.
                Packets exceeding this size will be truncated.
            timeout: Maximum time to wait for a packet in seconds.
                If `None`, blocks indefinitely.

        Returns:
            A :class:`pydivert.Packet` instance containing the raw bytes and
            parsed protocol headers.

        Raises:
            RuntimeError: If the handle is closed.
            TimeoutError: If no packet arrives within the `timeout` period.
            OSError: If a low-level capture error occurs in the OS driver.
        """
        return self._impl.recv(bufsize, timeout)

    async def recv_async(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        """
        Asynchronous version of `recv()`.
        Yields control while waiting for a packet.

        :param bufsize: The maximum size of the packet to receive.
        :param timeout: Maximum time to wait for a packet (in seconds).
        :return: A `pydivert.Packet` instance.
        """
        return await self._impl.recv_async(bufsize, timeout)

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """
        Reinjects a packet into the network stack.

        This is used to release an intercepted packet (modified or not) or to
        inject entirely new packets into the network path.

        ### Loop Prevention:
        - **Windows:** The WinDivert driver automatically marks reinjected packets
          to ensure they aren't captured by the same handle again.
        - **Linux:** PyDivert applies a specific `SO_MARK` (0x4D49544M) to the
          reinjection socket. The eBPF program ignores any packet carrying this
          mark to prevent infinite capture loops.

        Args:
            packet: The :class:`pydivert.Packet` object to send.
            recalculate_checksum: If `True` (default), PyDivert will automatically
                recompute IP, TCP, UDP, and ICMP checksums. This is mandatory if
                you modified the payload or header fields.

        Returns:
            The number of bytes successfully injected.

        Raises:
            RuntimeError: If the handle is closed.
            ValueError: If the packet object is malformed or lacks necessary headers.
            OSError: If the OS refuses to inject the packet (e.g., due to invalid
                IP headers or routing failures).
        """
        return self._impl.send(packet, recalculate_checksum)

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """
        Asynchronous version of `send()`.

        :param packet: The `pydivert.Packet` to send.
        :param recalculate_checksum: If `True`, recalculate checksums.
        :return: Number of bytes sent.
        """
        return await self._impl.send_async(packet, recalculate_checksum)

    def __getattr__(self, name: str):
        return getattr(self._impl, name)

    def __dir__(self) -> list[str]:
        return sorted(set(super().__dir__()) | set(dir(self._impl)))
