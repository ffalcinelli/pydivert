# -*- coding: utf-8 -*-
# Copyright (C) 2016  Fabio Falcinelli, Maximilian Hils
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
from ctypes import byref, c_uint64, c_uint, c_char, c_char_p

from . import windivert_dll
from .consts import Layer, Flag, Priority
from .packet import Packet
from .util import PY2

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

    def __init__(self, filter="true", layer=Layer.NETWORK, priority=Priority.DEFAULT, flags=Flag.DEFAULT):
        self._handle = None
        self._filter = filter.encode()
        self._layer = layer
        self._priority = priority
        self._flags = flags
        if not self._flags:
            if self._layer == Layer.FLOW:
                self._flags |= Flag.SNIFF | Flag.RECV_ONLY
            elif self._layer == Layer.SOCKET:
                self._flags |= Flag.RECV_ONLY
            elif self._layer == Layer.REFLECT:
                self._flags |= Flag.SNIFF | Flag.RECV_ONLY

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
    def compile_filter(filter, layer=Layer.NETWORK):
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
        obl = 128 + len(filter) * 2
        obj = bytes(bytearray(obl))
        res, pos, msg = False, c_uint(), c_char_p()
        try:
            res = windivert_dll.WinDivertHelperCompileFilter(filter.encode(), layer, obj, obl, byref(msg), byref(pos))
        except OSError as e:
            pass
        return res, obj.rstrip(b"\0"), pos.value, msg.value.decode()

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
        self._handle = windivert_dll.WinDivertOpen(self._filter, self._layer, self._priority, self._flags)

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

        WINDIVERTEXPORT BOOL WinDivertRecv(
        __in        HANDLE handle,
        __out_opt   VOID *pPacket,
        __in        UINT packetLen,
        __out_opt   UINT *pRecvLen,
        __out_opt   WINDIVERT_ADDRESS *pAddr);

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
        return Packet(memoryview(packet)[:recv_len.value], self._layer, address)


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
                __in PWINDIVERT_ADDRESS pAddr,
                __out_opt UINT *sendLen
            );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_send

        :return: The return value is the number of bytes actually sent.
        """
        if recalculate_checksum:
            packet.recalculate_checksums()

        send_len = c_uint(0)
        if PY2:
            # .from_buffer(memoryview) does not work on PY2
            buff = bytearray(packet.raw)
        else:
            buff = packet.raw
        buff = (c_char * len(packet.raw)).from_buffer(buff)
        windivert_dll.WinDivertSend(self._handle, buff, len(packet.raw), byref(send_len), byref(packet.wd_addr))
        return send_len

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
