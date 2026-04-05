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

import asyncio
import ctypes
import logging
import subprocess
from ctypes import byref, c_char, c_char_p, c_uint, c_uint64

from pydivert import service, windivert_dll  # noqa: F401
from pydivert.consts import Direction, Flag, Layer, Param
from pydivert.packet import Packet
from pydivert.windivert_dll import Overlapped, WinDivertAddress

DEFAULT_PACKET_BUFFER_SIZE = 65575

logger = logging.getLogger(__name__)


class WinDivert:
    """
    A WinDivert handle that can be used to capture packets.
    The main methods are `.open()`, `.recv()`, `.send()` and `.close()`.

    Use it like so::

        with pydivert.WinDivert() as w:
            for packet in w:
                print(packet)
                w.send(packet)

    """

    def __init__(
        self, filter: str = "true", layer: Layer = Layer.NETWORK, priority: int = 0, flags: Flag = Flag.DEFAULT
    ) -> None:
        """
        Creates a WinDivert handle.

        :param filter: The packet filter string (e.g. "tcp.DstPort == 80").
        :param layer: The WinDivert layer (e.g. Layer.NETWORK, Layer.FLOW).
        :param priority: The priority of the handle (higher priority handles see packets first).
        :param flags: WinDivert flags (e.g. Flag.SNIFF, Flag.DROP).
        """
        self._handle = None
        self._filter = filter.encode()
        self._layer = layer
        self._priority = priority
        self._flags = flags
        self._recv_buf = None
        self._recv_buf_c = None

    def __repr__(self):
        state = "open" if self._handle is not None else "closed"
        filter_str = self._filter.decode()
        return (
            f'<WinDivert state="{state}" filter="{filter_str}" layer="{self._layer}" '
            f'priority="{self._priority}" flags="{self._flags}" />'
        )

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def __iter__(self):
        return self

    def __next__(self):
        return self.recv()

    async def __aenter__(self) -> "WinDivert":
        self.open()
        return self

    async def __aexit__(self, *args) -> None:
        self.close()

    def __aiter__(self):
        return self

    async def __anext__(self) -> Packet:
        return await self.recv_async()

    @staticmethod
    def register():
        """
        An utility method to register the service the first time.
        It is usually not required to call this function, as WinDivert will register itself when opening a handle.
        """
        with WinDivert("false"):
            pass

    @staticmethod
    def is_registered():
        """
        Check if the WinDivert service is currently installed on the system.
        """
        return subprocess.run(["sc", "query", "WinDivert"], capture_output=True).returncode == 0

    @staticmethod
    def unregister():
        """
        Unregisters the WinDivert service.
        This function only requests a service stop, which may not be processed immediately if there are still open
        handles.
        """
        subprocess.run(["sc", "stop", "WinDivert"], capture_output=True, check=True)

    @staticmethod
    def check_filter(filter: str, layer: Layer = Layer.NETWORK) -> tuple[bool, int, str]:
        """
        Checks if the given packet filter string is valid with respect to the filter language.

        The remapped function is WinDivertHelperCheckFilter::

            BOOL WinDivertHelperCheckFilter(
                __in const char *filter,
                __in WINDIVERT_LAYER layer,
                __out_opt const char **errorStr,
                __out_opt UINT *errorPos
            );

        See: https://reqrypt.org/windivert-doc.html#divert_helper_check_filter

        :return: A tuple (res, pos, msg) with check result in 'res' human readable description of the error in 'msg'
            and the error's position in 'pos'.
        """
        res, pos, msg = False, c_uint(), c_char_p()
        try:
            res = windivert_dll.WinDivertHelperCompileFilter(filter.encode(), layer, None, 0, byref(msg), byref(pos))  # type: ignore[attr-defined]
        except OSError as e:
            logger.warning("WinDivertHelperCompileFilter failed: %s", e)
        return res, pos.value, msg.value.decode() if msg.value else ""

    def open(self) -> None:
        """
        Opens a WinDivert handle for the given filter.
        Unless otherwise specified by flags, any packet that matches the filter will be diverted to the handle.
        Diverted packets can be read by the application with receive().

        The remapped function is WinDivertOpen::

            HANDLE WinDivertOpen(
                __in const char *filter,
                __in WINDIVERT_LAYER layer,
                __in INT16 priority,
                __in UINT64 flags
            );

        For more info on the C call visit: https://reqrypt.org/windivert-doc.html#divert_open
        """
        if self.is_open:
            raise RuntimeError("WinDivert handle is already open.")
        self._handle = windivert_dll.WinDivertOpen(self._filter, self._layer, self._priority, self._flags)  # type: ignore[attr-defined]

    @property
    def is_open(self):
        """
        Indicates if there is currently an open handle.
        """
        return bool(self._handle)

    def close(self) -> None:
        """
        Closes the handle opened by open().

        The remapped function is WinDivertClose::

            BOOL WinDivertClose(
                __in HANDLE handle
            );

        For more info on the C call visit: https://reqrypt.org/windivert-doc.html#divert_close
        """
        if not self.is_open:
            raise RuntimeError("WinDivert handle is not open.")
        windivert_dll.WinDivertClose(self._handle)  # type: ignore[attr-defined]
        self._handle = None

    def recv(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE) -> Packet:
        """
        Receives a diverted packet that matched the filter.

        The remapped function is WinDivertRecv::

            BOOL WinDivertRecv(
                __in HANDLE handle,
                __out PVOID pPacket,
                __in UINT packetLen,
                __out_opt UINT *pRecvLen,
                __out_opt PWINDIVERT_ADDRESS pAddr
            );

        For more info on the C call visit: https://reqrypt.org/windivert-doc.html#divert_recv

        :return: The return value is a `pydivert.Packet`.
        """
        if self._handle is None:
            raise RuntimeError("WinDivert handle is not open")

        if self._recv_buf is None or len(self._recv_buf) != bufsize:
            self._recv_buf = bytearray(bufsize)
            self._recv_buf_c = (c_char * bufsize).from_buffer(self._recv_buf)

        packet = self._recv_buf
        packet_ = self._recv_buf_c
        address = WinDivertAddress()
        recv_len = c_uint(0)
        windivert_dll.WinDivertRecv(self._handle, packet_, bufsize, byref(recv_len), byref(address))  # type: ignore[attr-defined]

        return self._parse_packet(packet[: recv_len.value], recv_len.value, address)

    async def recv_async(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE) -> Packet:
        """
        Asynchronously receives a diverted packet.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.recv, bufsize)

    @staticmethod
    def _parse_packet(packet, recv_len, address):
        """
        Helper method to parse a raw packet buffer and a WinDivertAddress structure
        into a pydivert.Packet instance.
        """
        return Packet(
            packet[:recv_len] if isinstance(packet, memoryview) else memoryview(packet)[:recv_len],
            interface=(address.Network.IfIdx, address.Network.SubIfIdx),
            direction=Direction.OUTBOUND if address.Outbound else Direction.INBOUND,
            timestamp=address.Timestamp,
            loopback=bool(address.Loopback),
            impostor=bool(address.Impostor),
            sniffed=bool(address.Sniffed),
            ip_checksum=bool(address.IPChecksum),
            tcp_checksum=bool(address.TCPChecksum),
            udp_checksum=bool(address.UDPChecksum),
            layer=address.Layer,
            event=address.Event,
            flow=address.Flow if address.Layer == Layer.FLOW else None,
            socket=address.Socket if address.Layer == Layer.SOCKET else None,
            reflect=address.Reflect if address.Layer == Layer.REFLECT else None,
        )

    def recv_ex(
        self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, flags: int = 0, overlapped: Overlapped | None = None
    ) -> Packet | None:
        """
        Receives a diverted packet that matched the filter (extended version).
        Supports overlapped IO.

        The remapped function is WinDivertRecvEx::

            BOOL WinDivertRecvEx(
                __in HANDLE handle,
                __out PVOID pPacket,
                __in UINT packetLen,
                __out_opt UINT *pRecvLen,
                __in UINT64 flags,
                __out PWINDIVERT_ADDRESS pAddr,
                __inout_opt UINT *pAddrLen,
                __inout_opt LPOVERLAPPED lpOverlapped
            );

        For more info on the C call visit: https://reqrypt.org/windivert-doc.html#divert_recv

        :param bufsize: The size of the packet buffer.
        :param flags: WinDivert receive flags (e.g. RecvFlag.NO_BLOCK).
        :param overlapped: An optional `Overlapped` structure for overlapped IO.
        :return: A `pydivert.Packet` if synchronous, or `None` if `ERROR_IO_PENDING` occurred.
        """
        if self._handle is None:
            raise RuntimeError("WinDivert handle is not open")

        if overlapped is None:
            if self._recv_buf is None or len(self._recv_buf) != bufsize:
                self._recv_buf = bytearray(bufsize)
                self._recv_buf_c = (c_char * bufsize).from_buffer(self._recv_buf)
            packet = self._recv_buf
            packet_ = self._recv_buf_c
        else:
            packet = bytearray(bufsize)
            packet_ = (c_char * bufsize).from_buffer(packet)
        windivert_dll._init()

        address = WinDivertAddress()
        recv_len = c_uint(0)
        addr_len = c_uint(ctypes.sizeof(WinDivertAddress))

        try:
            windivert_dll.WinDivertRecvEx(  # type: ignore[attr-defined]
                self._handle, packet_, bufsize, byref(recv_len), flags, byref(address), byref(addr_len), overlapped
            )
        except OSError as e:
            if overlapped is not None and getattr(e, "winerror", None) == windivert_dll.ERROR_IO_PENDING:
                # Store references to prevent garbage collection
                overlapped._packet_buffer = packet
                overlapped._address = address
                overlapped._recv_len = recv_len
                return None
            raise

        if overlapped is None:
            return self._parse_packet(packet[: recv_len.value], recv_len.value, address)
        else:
            return self._parse_packet(packet, recv_len.value, address)

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """
        Injects a packet into the network stack.
        Recalculates the checksum before sending unless recalculate_checksum=False is passed.

        The injected packet may be one received from recv(), or a modified version, or a completely new packet.
        Injected packets can be captured and diverted again by other WinDivert handles with lower priorities.

        The remapped function is WinDivertSend::

            BOOL WinDivertSend(
                __in HANDLE handle,
                __in PVOID pPacket,
                __in UINT packetLen,
                __out_opt UINT *pSendLen,
                __in const PWINDIVERT_ADDRESS pAddr
            );

        For more info on the C call visit: https://reqrypt.org/windivert-doc.html#divert_send

        :return: The return value is the number of bytes actually sent.
        """
        if recalculate_checksum:
            packet.recalculate_checksums()

        send_len = c_uint(0)
        raw = packet.raw
        buff = (c_char * len(packet.raw)).from_buffer(raw)
        windivert_dll.WinDivertSend(self._handle, buff, len(packet.raw), byref(send_len), byref(packet.wd_addr))  # type: ignore[attr-defined]
        return send_len.value

    async def send_async(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        """
        Asynchronously injects a packet into the network stack.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.send, packet, recalculate_checksum)

    def send_ex(
        self, packet: Packet, recalculate_checksum: bool = True, flags: int = 0, overlapped: Overlapped | None = None
    ) -> int | None:
        """
        Injects a packet into the network stack (extended version).
        Recalculates the checksum before sending unless recalculate_checksum=False is passed.
        Supports overlapped IO.

        The remapped function is WinDivertSendEx::

            BOOL WinDivertSendEx(
                __in HANDLE handle,
                __in PVOID pPacket,
                __in UINT packetLen,
                __out_opt UINT *pSendLen,
                __in UINT64 flags,
                __in const PWINDIVERT_ADDRESS pAddr,
                __in UINT addrLen,
                __inout_opt LPOVERLAPPED lpOverlapped
            );

        For more info on the C call visit: https://reqrypt.org/windivert-doc.html#divert_send

        :param packet: The packet to send.
        :param recalculate_checksum: Whether to recalculate checksums before sending.
        :param flags: WinDivert send flags (currently unused, should be 0).
        :param overlapped: An optional `Overlapped` structure for overlapped IO.
        :return: The number of bytes sent if synchronous, or `None` if `ERROR_IO_PENDING` occurred.
        """
        if recalculate_checksum:
            packet.recalculate_checksums()

        send_len = c_uint(0)
        raw = packet.raw
        buff = (c_char * len(packet.raw)).from_buffer(raw)
        windivert_dll._init()

        wd_addr = packet.wd_addr
        addr_len = ctypes.sizeof(WinDivertAddress)

        try:
            windivert_dll.WinDivertSendEx(  # type: ignore[attr-defined]
                self._handle, buff, len(packet.raw), byref(send_len), flags, byref(wd_addr), addr_len, overlapped
            )
        except OSError as e:
            if overlapped is not None and getattr(e, "winerror", None) == windivert_dll.ERROR_IO_PENDING:
                # Store references to prevent garbage collection
                overlapped._packet_raw = packet.raw
                overlapped._address = wd_addr
                overlapped._send_len = send_len
                return None
            raise

        return send_len.value

    def get_param(self, name: Param) -> int:
        """
        Get a WinDivert parameter. See pydivert.Param for the list of parameters.

        The remapped function is WinDivertGetParam::

            BOOL WinDivertGetParam(
                __in HANDLE handle,
                __in WINDIVERT_PARAM param,
                __out UINT64 *pValue
            );

        For more info on the C call visit: https://reqrypt.org/windivert-doc.html#divert_get_param

        :return: The parameter value.
        """
        value = c_uint64(0)
        windivert_dll.WinDivertGetParam(self._handle, name, byref(value))  # type: ignore[attr-defined]
        return value.value

    def set_param(self, name: Param, value: int) -> int:
        """
        Set a WinDivert parameter. See pydivert.Param for the list of parameters.

        The remapped function is DivertSetParam::

            BOOL WinDivertSetParam(
                __in HANDLE handle,
                __in WINDIVERT_PARAM param,
                __in UINT64 value
            );

        For more info on the C call visit: https://reqrypt.org/windivert-doc.html#divert_set_param
        """
        return windivert_dll.WinDivertSetParam(self._handle, name, value)  # type: ignore[attr-defined]
