# -*- coding: utf-8 -*-
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import subprocess
import sys
import ctypes
from ctypes import byref, c_uint64, c_uint, c_char, c_char_p

from pydivert import windivert_dll
from pydivert.consts import Layer, Direction, Flag
from pydivert.packet import Packet

DEFAULT_PACKET_BUFFER_SIZE = 1500


class WinDivert(object):
    """
    A WinDivert handle that can be used to capture packets.
    The main methods are `.open()`, `.recv()`, `.send()` and `.close()`.

    Use it like so::

        with pydivert.WinDivert() as w:
            for packet in w:
                print(packet)
                w.send(packet)

    """

    def __init__(self, filter="true", layer=Layer.NETWORK, priority=0, flags=Flag.DEFAULT):
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

    def __repr__(self):
        return '<WinDivert state="{}" filter="{}" layer="{}" priority="{}" flags="{}" />'.format(
            "open" if self._handle is not None else "closed",
            self._filter.decode(),
            self._layer,
            self._priority,
            self._flags
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

    if sys.version_info < (3, 0):
        next = __next__

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
        return subprocess.call("sc query WinDivert", stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE) == 0

    @staticmethod
    def unregister():
        """
        Unregisters the WinDivert service.
        This function only requests a service stop, which may not be processed immediately if there are still open
        handles.
        """
        subprocess.check_call("sc stop WinDivert", stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

    @staticmethod
    def check_filter(filter, layer=Layer.NETWORK):
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

        :return: A tuple (res, pos, msg) with check result in 'res' human readable description of the error in 'msg' and the error's position in 'pos'.
        """
        res, pos, msg = False, c_uint(), c_char_p()
        try:
            res = windivert_dll.WinDivertHelperCompileFilter(filter.encode(), layer, None, 0, byref(msg), byref(pos))
        except OSError:
            pass
        return res, pos.value, msg.value.decode() if msg.value else ""

    def open(self):
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

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_open
        """
        if self.is_open:
            raise RuntimeError("WinDivert handle is already open.")
        self._handle = windivert_dll.WinDivertOpen(self._filter, self._layer, self._priority,
                                                   self._flags)

    @property
    def is_open(self):
        """
        Indicates if there is currently an open handle.
        """
        return bool(self._handle)

    def close(self):
        """
        Closes the handle opened by open().

        The remapped function is WinDivertClose::

            BOOL WinDivertClose(
                __in HANDLE handle
            );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_close
        """
        if not self.is_open:
            raise RuntimeError("WinDivert handle is not open.")
        windivert_dll.WinDivertClose(self._handle)
        self._handle = None

    def recv(self, bufsize=DEFAULT_PACKET_BUFFER_SIZE):
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

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_recv

        :return: The return value is a `pydivert.Packet`.
        """
        if self._handle is None:
            raise RuntimeError("WinDivert handle is not open")

        packet = bytearray(bufsize)
        packet_ = (c_char * bufsize).from_buffer(packet)
        address = windivert_dll.WinDivertAddress()
        recv_len = c_uint(0)
        windivert_dll.WinDivertRecv(self._handle, packet_, bufsize, byref(recv_len), byref(address))
        return Packet(
            memoryview(packet)[:recv_len.value],
            (address.Network.IfIdx, address.Network.SubIfIdx),
            Direction.OUTBOUND if address.Outbound else Direction.INBOUND,
            timestamp=address.Timestamp,
            loopback=bool(address.Loopback),
            impostor=bool(address.Impostor),
            sniffed=bool(address.Sniffed),
            ip_checksum=bool(address.IPChecksum),
            tcp_checksum=bool(address.TCPChecksum),
            udp_checksum=bool(address.UDPChecksum)
        )

    def recv_ex(self, bufsize=DEFAULT_PACKET_BUFFER_SIZE, flags=0, overlapped=None):
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

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_recv

        :param bufsize: The size of the packet buffer.
        :param flags: WinDivert receive flags (e.g. RecvFlag.NO_BLOCK).
        :param overlapped: An optional `pydivert.windivert_dll.Overlapped` structure for overlapped IO.
        :return: A `pydivert.Packet` if synchronous, or `None` if `ERROR_IO_PENDING` occurred.
        """
        if self._handle is None:
            raise RuntimeError("WinDivert handle is not open")

        packet = bytearray(bufsize)
        packet_ = (c_char * bufsize).from_buffer(packet)
        windivert_dll._init()
        from pydivert.windivert_dll.structs import WinDivertAddress
        address = WinDivertAddress()
        recv_len = c_uint(0)
        addr_len = c_uint(ctypes.sizeof(WinDivertAddress))

        try:
            windivert_dll.WinDivertRecvEx(self._handle, packet_, bufsize, byref(recv_len), flags,
                                          byref(address), byref(addr_len), overlapped)
        except OSError as e:
            if overlapped is not None and e.winerror == windivert_dll.ERROR_IO_PENDING:
                # Store references to prevent garbage collection
                overlapped._packet_buffer = packet
                overlapped._address = address
                overlapped._recv_len = recv_len
                return None
            raise

        return Packet(
            memoryview(packet)[:recv_len.value],
            (address.Network.IfIdx, address.Network.SubIfIdx),
            Direction.OUTBOUND if address.Outbound else Direction.INBOUND,
            timestamp=address.Timestamp,
            loopback=bool(address.Loopback),
            impostor=bool(address.Impostor),
            sniffed=bool(address.Sniffed),
            ip_checksum=bool(address.IPChecksum),
            tcp_checksum=bool(address.TCPChecksum),
            udp_checksum=bool(address.UDPChecksum)
        )

    def send(self, packet, recalculate_checksum=True):
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

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_send

        :return: The return value is the number of bytes actually sent.
        """
        if recalculate_checksum:
            packet.recalculate_checksums()

        send_len = c_uint(0)
        buff = packet.raw
        buff = (c_char * len(packet.raw)).from_buffer(buff)
        windivert_dll.WinDivertSend(self._handle, buff, len(packet.raw), byref(send_len), byref(packet.wd_addr))
        return send_len.value

    def send_ex(self, packet, recalculate_checksum=True, flags=0, overlapped=None):
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

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_send

        :param packet: The packet to send.
        :param recalculate_checksum: Whether to recalculate checksums before sending.
        :param flags: WinDivert send flags (currently unused, should be 0).
        :param overlapped: An optional `pydivert.windivert_dll.Overlapped` structure for overlapped IO.
        :return: The number of bytes sent if synchronous, or `None` if `ERROR_IO_PENDING` occurred.
        """
        if recalculate_checksum:
            packet.recalculate_checksums()

        send_len = c_uint(0)
        buff = packet.raw
        buff = (c_char * len(packet.raw)).from_buffer(buff)
        windivert_dll._init()
        from pydivert.windivert_dll.structs import WinDivertAddress
        wd_addr = packet.wd_addr
        addr_len = ctypes.sizeof(WinDivertAddress)

        try:
            windivert_dll.WinDivertSendEx(self._handle, buff, len(packet.raw), byref(send_len), flags,
                                          byref(wd_addr), addr_len, overlapped)
        except OSError as e:
            if overlapped is not None and e.winerror == windivert_dll.ERROR_IO_PENDING:
                # Store references to prevent garbage collection
                overlapped._packet_raw = packet.raw
                overlapped._address = wd_addr
                overlapped._send_len = send_len
                return None
            raise

        return send_len.value

    def get_param(self, name):
        """
        Get a WinDivert parameter. See pydivert.Param for the list of parameters.

        The remapped function is WinDivertGetParam::

            BOOL WinDivertGetParam(
                __in HANDLE handle,
                __in WINDIVERT_PARAM param,
                __out UINT64 *pValue
            );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_get_param

        :return: The parameter value.
        """
        value = c_uint64(0)
        windivert_dll.WinDivertGetParam(self._handle, name, byref(value))
        return value.value

    def set_param(self, name, value):
        """
        Set a WinDivert parameter. See pydivert.Param for the list of parameters.

        The remapped function is DivertSetParam::

            BOOL WinDivertSetParam(
                __in HANDLE handle,
                __in WINDIVERT_PARAM param,
                __in UINT64 value
            );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_set_param
        """
        return windivert_dll.WinDivertSetParam(self._handle, name, value)
