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
import os
import subprocess
from ctypes import byref, c_char, c_char_p, c_uint, c_uint64
from typing import Any

from pydivert import service, windivert_dll  # noqa: F401
from pydivert.base import BaseDivert
from pydivert.consts import (
    DEFAULT_PACKET_BUFFER_SIZE,
    Direction,
    Flag,
    Layer,
    Param,
)
from pydivert.packet import Packet
from pydivert.windivert_dll import (
    INFINITE,
    Overlapped,
    WinDivertAddress,
)

logger = logging.getLogger(__name__)


class WinDivert(BaseDivert):
    """
    A WinDivert handle that can be used to capture packets.
    """

    def __init__(
        self, filter: str = "true", layer: Layer = Layer.NETWORK, priority: int = 0, flags: Flag = Flag.DEFAULT
    ) -> None:
        if os.name != "nt":
            raise OSError("WinDivert is only supported on Windows.")
        super().__init__(filter, layer, priority, flags)
        self._handle = None
        self._event = None
        self._recv_buf = None
        self._recv_buf_c = None
        self._pending_ops: list[Overlapped] = []

    @staticmethod
    def register():
        """
        An utility method to register the service the first time.
        """
        with WinDivert("false"):
            pass

    @staticmethod
    def is_registered() -> bool:
        """
        Check if the WinDivert service is currently installed on the system.
        """
        return service.is_registered()

    @staticmethod
    def unregister() -> None:
        """
        Unregisters the WinDivert service.
        """
        if not service.stop_service():
            # Fallback to sc.exe if direct Win32 API fails
            try:
                import ctypes.wintypes

                buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
                length = ctypes.windll.kernel32.GetSystemDirectoryW(buf, ctypes.wintypes.MAX_PATH)
                if 0 < length <= ctypes.wintypes.MAX_PATH:
                    system32 = buf.value
                else:
                    system32 = "C:\\Windows\\System32"
            except (AttributeError, OSError, ImportError):
                system32 = "C:\\Windows\\System32"

            sc_path = os.path.join(system32, "sc.exe")
            subprocess.run([sc_path, "stop", "WinDivert"], capture_output=True, check=True)

    @staticmethod
    def check_filter(filter: str, layer: Layer = Layer.NETWORK) -> tuple[bool, int, str]:
        """
        Checks if the given packet filter string is valid with respect to the filter language.
        """
        res, pos, msg = False, c_uint(), c_char_p()
        try:
            res = windivert_dll.WinDivertHelperCompileFilter(filter.encode(), layer, None, 0, byref(msg), byref(pos))
        except OSError as e:
            logger.warning("WinDivertHelperCompileFilter failed: %s", e)
        return res, pos.value, msg.value.decode() if msg.value else ""

    def _open_impl(self) -> None:
        self._handle = windivert_dll.WinDivertOpen(self.filter.encode(), self.layer, self.priority, self.flags)
        self._event = windivert_dll.CreateEventW(None, False, False, None)

    def _close_impl(self) -> None:
        windivert_dll.WinDivertClose(self._handle)
        self._handle = None
        self._pending_ops.clear()
        if self._event:
            windivert_dll.CloseHandle(self._event)
            self._event = None

    def _recv_impl(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        if self._recv_buf is None or len(self._recv_buf) != bufsize:
            self._recv_buf = bytearray(bufsize)
            self._recv_buf_c = (c_char * bufsize).from_buffer(self._recv_buf)

        packet = self._recv_buf
        packet_ = self._recv_buf_c
        address = WinDivertAddress()
        recv_len = c_uint(0)
        windivert_dll.WinDivertRecv(self._handle, packet_, bufsize, byref(recv_len), byref(address))

        return self._parse_packet(packet[: recv_len.value], recv_len.value, address)

    async def _recv_async_impl(self, bufsize: int = DEFAULT_PACKET_BUFFER_SIZE, timeout: float | None = None) -> Packet:
        if self._recv_buf is None or len(self._recv_buf) != bufsize:
            self._recv_buf = bytearray(bufsize)
            self._recv_buf_c = (c_char * bufsize).from_buffer(self._recv_buf)

        packet = self._recv_buf
        packet_ = self._recv_buf_c
        address = WinDivertAddress()
        recv_len = c_uint(0)
        overlapped = Overlapped(hEvent=self._event)

        overlapped._packet = packet
        overlapped._address = address
        overlapped._recv_len = recv_len
        self._pending_ops.append(overlapped)

        try:
            res = windivert_dll.WinDivertRecvEx(
                self._handle, packet_, bufsize, byref(recv_len), 0, byref(address), None, byref(overlapped)
            )

            if not res:
                error = windivert_dll.GetLastError()
                if error == windivert_dll.ERROR_IO_PENDING:
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, windivert_dll.WaitForSingleObject, self._event, INFINITE)
                else:
                    raise windivert_dll.WinError(error)
            self._pending_ops.remove(overlapped)
            return self._parse_packet(packet[: recv_len.value], recv_len.value, address)
        except asyncio.CancelledError:
            raise
        except Exception:
            if overlapped in self._pending_ops:
                self._pending_ops.remove(overlapped)
            raise

    @staticmethod
    def _parse_packet(packet, recv_len, address):
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
            wd_addr=address,
        )

    def _send_impl(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        if recalculate_checksum:
            packet.recalculate_checksums()

        send_len = c_uint(0)
        raw = packet.raw
        buff = (c_char * len(packet.raw)).from_buffer(raw)
        windivert_dll.WinDivertSend(self._handle, buff, len(packet.raw), byref(send_len), byref(packet.wd_addr))
        return send_len.value

    async def _send_async_impl(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        if recalculate_checksum:
            packet.recalculate_checksums()

        send_len = c_uint(0)
        raw = packet.raw
        buff = (c_char * len(packet.raw)).from_buffer(raw)
        wd_addr = packet.wd_addr
        overlapped = Overlapped(hEvent=self._event)

        overlapped._packet = packet
        overlapped._buff = buff
        overlapped._wd_addr = wd_addr
        overlapped._send_len = send_len
        self._pending_ops.append(overlapped)

        try:
            res = windivert_dll.WinDivertSendEx(
                self._handle,
                buff,
                len(packet.raw),
                byref(send_len),
                0,
                byref(wd_addr),
                ctypes.sizeof(WinDivertAddress),
                byref(overlapped),
            )

            if not res:
                error = windivert_dll.GetLastError()
                if error == windivert_dll.ERROR_IO_PENDING:
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, windivert_dll.WaitForSingleObject, self._event, INFINITE)
                else:
                    raise windivert_dll.WinError(error)

            self._pending_ops.remove(overlapped)
            return send_len.value
        except asyncio.CancelledError:
            raise
        except Exception:
            if overlapped in self._pending_ops:
                self._pending_ops.remove(overlapped)
            raise

    def get_param(self, name: Param) -> int:
        """
        Get a WinDivert parameter.
        """
        if self._handle is None:
            raise RuntimeError("WinDivert handle is not open")

        value = c_uint64(0)
        windivert_dll.WinDivertGetParam(self._handle, name, byref(value))
        return value.value

    def set_param(self, name: Param, value: int) -> int:
        """
        Set a WinDivert parameter.
        """
        if self._handle is None:
            raise RuntimeError("WinDivert handle is not open")

        return windivert_dll.WinDivertSetParam(self._handle, name, value)
