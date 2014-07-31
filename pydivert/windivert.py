# -*- coding: utf-8 -*-
# Copyright (C) 2013  Fabio Falcinelli
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from _ctypes import POINTER, pointer, byref, sizeof
from ctypes.wintypes import HANDLE
import os
from ctypes import (c_uint, c_void_p, c_uint32, c_char_p, ARRAY, c_uint64, c_int16, c_int, WinDLL,
                    create_string_buffer, c_uint8)
import logging
import sys

from pydivert.decorators import winerror_on_retcode, cd
from pydivert.enum import Layer, RegKeys, Defaults, ErrorCodes
from pydivert.exception import AsyncCallFailedException, MethodUnsupportedException
from pydivert.winutils import get_reg_values, GetLastError
from pydivert.models import WinDivertAddress, IpHeader, Ipv6Header, IcmpHeader, Icmpv6Header, FuturePacket
from pydivert.models import TcpHeader, UdpHeader, CapturedPacket, CapturedMetadata, HeaderWrapper


__author__ = 'fabio'

#TODO: move the logger away... Probably better inside WinDivert class
logger = logging.getLogger(__name__)


class WinDivert(object):
    """
    Python interface for WinDivert.dll library.
    """

    dll_argtypes = {"WinDivertHelperParsePacket": [HANDLE, c_uint, c_void_p, c_void_p, c_void_p,
                                                   c_void_p, c_void_p, c_void_p, c_void_p, POINTER(c_uint)],
                    "WinDivertHelperParseIPv4Address": [c_char_p, POINTER(c_uint32)],
                    "WinDivertHelperParseIPv6Address": [c_char_p, POINTER(ARRAY(c_uint8, 16))],
                    "WinDivertHelperCalcChecksums": [c_void_p, c_uint, c_uint64],
                    "WinDivertOpen": [c_char_p, c_int, c_int16, c_uint64],
                    "WinDivertRecv": [HANDLE, c_void_p, c_uint, c_void_p, c_void_p],
                    "WinDivertSend": [HANDLE, c_void_p, c_uint, c_void_p, c_void_p],
                    "WinDivertRecvEx": [HANDLE, c_void_p, c_uint, c_uint64, c_void_p, c_void_p, c_void_p],
                    "WinDivertSendEx": [HANDLE, c_void_p, c_uint, c_uint64, c_void_p, c_void_p, c_void_p],
                    "WinDivertClose": [HANDLE],
                    "WinDivertGetParam": [HANDLE, c_int, POINTER(c_uint64)],
                    "WinDivertSetParam": [HANDLE, c_int, c_uint64],
    }

    class LegacyDLLWrapper(object):
        """
        A wrapper object to seamlessy call the 1.0 api instead of the 1.1
        """
        _lib = None

        def __init__(self, dll):
            self._lib = dll

        def __getattr__(self, item):
            if item in WinDivert.dll_argtypes.keys():
                return getattr(self._lib, item[3:])
            else:
                return getattr(self._lib, item)

        def __setattr__(self, key, value):
            if key == "_lib":
                super(WinDivert.LegacyDLLWrapper, self).__setattr__(key, value)
                return

            if key in WinDivert.dll_argtypes.keys():
                return setattr(self._lib, key[3:], value)
            else:
                return setattr(self._lib, key, value)

    def _load_dll(self, dll_path):
        """
        Loads the WinDivert.dll library, configuring it according to its version
        :param dll_path: The OS path where to load the WinDivert.dll
        :return:
        """
        self._lib = WinDLL(dll_path)
        self.reg_key = RegKeys.VERSION11
        if not hasattr(self._lib, "WinDivertOpen"):
            logger.debug("Library does not seem to be of version >= 1.1. Assuming 1.0...")
            self.reg_key = RegKeys.VERSION10
            self._lib = self.LegacyDLLWrapper(self._lib)
            self.dll_argtypes = {k: v for k, v in self.dll_argtypes.items() if
                                 k not in ("WinDivertSendEx", "WinDivertRecvEx")}

        for funct, argtypes in self.dll_argtypes.items():
            setattr(getattr(self._lib, funct), "argtypes", argtypes)

    def __init__(self, dll_path=None, encoding="UTF-8"):
        """
        Constructs a new driver instance
        :param dll_path: The OS path where to load the WinDivert.dll
        :param encoding: The character encoding to use (defaults to UTF-8)
        :return:
        """
        if not dll_path:
            logger.debug("Trying to load dll from interpreter DLLs folder")
            dll_path = os.path.join(os.path.join(sys.exec_prefix, "DLLs", "WinDivert.dll"))
            if not os.path.exists(dll_path):
                raise ValueError("Unable to find WinDivert.dll")
        self.dll_path = dll_path
        self.encoding = encoding
        self._load_dll(dll_path)

    def open_handle(self, filter="true", layer=Layer.NETWORK, priority=0, flags=0):
        """
        Return a new handle already opened
        :param filter: The filter string, composed following the WinDivert filter's syntax
        :param layer: In which layer should be put (NETWORK|NETWORK_FORWARD)
        :param priority: Allows to configure a chain of filters, processing the packets in order of priority
        :param flags: An operational mode in SNIFF, DROP and NO_CHECKSUM
        :return: An opened Handle instance
        """
        return Handle(self, filter, layer, priority, flags, self.encoding).open()

    def get_reference(self):
        """
        Return a reference to the internal CDLL
        :return: The DLL object
        """
        return self._lib

    def is_legacy_driver(self):
        """
        Returns whether the driver is at the old 1.0.x version
        :return: True if a 1.0.x version is detected, False otherwise
        """
        return self.reg_key == RegKeys.VERSION10

    @winerror_on_retcode
    def parse_packet(self, *args):
        """
        Parses a raw packet into a higher level object.
        Args could be a tuple or two different values. In each case the first one is the raw data and the second
        is the meta about the direction and interface to use.

        The function remapped is WinDivertHelperParsePacket:
        Parses a raw packet (e.g. from WinDivertRecv()) into the various packet headers
        and/or payloads that may or may not be present.

        BOOL WinDivertHelperParsePacket(
            __in PVOID pPacket,
            __in UINT packetLen,
            __out_opt PWINDIVERT_IPHDR *ppIpHdr,
            __out_opt PWINDIVERT_IPV6HDR *ppIpv6Hdr,
            __out_opt PWINDIVERT_ICMPHDR *ppIcmpHdr,
            __out_opt PWINDIVERT_ICMPV6HDR *ppIcmpv6Hdr,
            __out_opt PWINDIVERT_TCPHDR *ppTcpHdr,
            __out_opt PWINDIVERT_UDPHDR *ppUdpHdr,
            __out_opt PVOID *ppData,
            __out_opt UINT *pDataLen
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_helper_parse_packet
        """
        if len(args) == 1:
            #Maybe this is a poor way to check the type, but it should work
            if hasattr(args[0], "__iter__") and not hasattr(args[0], "strip"):
                raw_packet, meta = args[0]
            else:
                raw_packet, meta = args[0], None
        elif len(args) == 2:
            raw_packet, meta = args[0], args[1]
        else:
            raise ValueError("Wrong number of arguments passed to parse_packet")

        packet_len = len(raw_packet)
        # Consider everything else not part of headers as payload
        # payload = ctypes.c_void_p(0)
        payload_len = c_uint(0)
        ip_hdr, ipv6_hdr = pointer(IpHeader()), pointer(Ipv6Header())
        icmp_hdr, icmpv6_hdr = pointer(IcmpHeader()), pointer(Icmpv6Header())
        tcp_hdr, udp_hdr = pointer(TcpHeader()), pointer(UdpHeader())
        headers = (ip_hdr, ipv6_hdr, icmp_hdr, icmpv6_hdr, tcp_hdr, udp_hdr)

        self._lib.WinDivertHelperParsePacket(raw_packet,
                                             packet_len,
                                             byref(ip_hdr),
                                             byref(ipv6_hdr),
                                             byref(icmp_hdr),
                                             byref(icmpv6_hdr),
                                             byref(tcp_hdr),
                                             byref(udp_hdr),
                                             None,
                                             byref(payload_len))
        #headers_len = sum(ctypes.sizeof(hdr.contents) for hdr in headers if hdr)
        #headers_len = sum((getattr(hdr.contents, "HdrLength", 0) * 4) for hdr in headers if hdr)

        # clean headers, consider just those that are not None (!=NULL)
        headers = [hdr.contents for hdr in headers if hdr]

        headers_opts = []
        offset = 0
        for header in headers:
            if hasattr(header, "HdrLength"):
                header_len = getattr(header, "HdrLength", 0) * 4
                opt_len = header_len - sizeof(header)
                if opt_len:
                    opt = raw_packet[offset + header_len - opt_len:offset + header_len]
                    headers_opts.append(opt)
                else:
                    headers_opts.append('')
            else:
                headers_opts.append('')
                header_len = sizeof(header)
            offset += header_len

        return CapturedPacket(payload=raw_packet[offset:],
                              raw_packet=raw_packet,
                              headers=[HeaderWrapper(hdr, opt, self.encoding) for hdr, opt in
                                       zip(headers, headers_opts)],
                              meta=meta,
                              encoding=self.encoding)

    @winerror_on_retcode
    def parse_ipv4_address(self, address):
        """
        Parses an IPv4 address.

        The function remapped is WinDivertHelperParseIPv4Address:

        BOOL WinDivertHelperParseIPv4Address(
            __in const char *addrStr,
            __out_opt UINT32 *pAddr
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_help_parse_ipv4_address
        """
        ip_addr = c_uint32(0)
        self._lib.WinDivertHelperParseIPv4Address(address.encode(self.encoding), byref(ip_addr))
        return ip_addr.value


    @winerror_on_retcode
    def parse_ipv6_address(self, address):
        """
        Parses an IPv6 address.

        The function remapped is WinDivertHelperParseIPv6Address:

        BOOL WinDivertHelperParseIPv6Address(
            __in const char *addrStr,
            __out_opt UINT32 *pAddr
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_help_parse_ipv6_address
        """
        ip_addr = ARRAY(c_uint8, 16)()
        self._lib.WinDivertHelperParseIPv6Address(address.encode(self.encoding), byref(ip_addr))
        return ip_addr

    @winerror_on_retcode
    def calc_checksums(self, packet, flags=0):
        """
        (Re)calculates the checksum for any IPv4/ICMP/ICMPv6/TCP/UDP checksum present in the given packet.
        Individual checksum calculations may be disabled via the appropriate flag.
        Typically this function should be invoked on a modified packet before it is injected with send().

        The function remapped is WinDivertHelperCalcChecksums:

        UINT WinDivertHelperCalcChecksums(
            __inout PVOID pPacket,
            __in UINT packetLen,
            __in UINT64 flags
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_helper_calc_checksums
        """
        packet_len = len(packet)
        buff = create_string_buffer(packet, packet_len)
        self._lib.WinDivertHelperCalcChecksums(byref(buff), packet_len, flags)
        return buff

    @winerror_on_retcode
    def update_packet_checksums(self, packet):
        """
        An utility shortcut method to update the checksums into an higher level packet
        """
        raw = self.calc_checksums(packet.raw)
        return self.parse_packet(raw, packet.meta)

    @winerror_on_retcode
    def register(self):
        """
        An utility method to register the driver the first time.
        """
        with cd(os.path.dirname(self.dll_path)):
            handle = self.open_handle("false")
            handle.close()
        return self

    @winerror_on_retcode
    def is_registered(self):
        """
        Check if an entry exist in windows registry
        """
        return hasattr(self, "registry") or get_reg_values(self.reg_key)

    def __str__(self):
        return "%s" % self._lib


class Handle(object):
    """
    An handle object got from a WinDivert DLL.
    """

    def __init__(self, driver=None, filter="true", layer=Layer.NETWORK, priority=0, flags=0, encoding="UTF-8"):
        if not driver:
            #Try to construct by loading from the registry
            self.driver = WinDivert()
        else:
            self.driver = driver
        self._lib = self.driver.get_reference()
        self._handle = None
        self.encoding = encoding
        self._filter = filter.encode(self.encoding)
        self._layer = layer
        self._priority = priority
        self._flags = flags

    @winerror_on_retcode
    def open(self):
        """
        Opens a WinDivert handle for the given filter.
        Unless otherwise specified by flags, any packet that matches the filter will be diverted to the handle.
        Diverted packets can be read by the application with receive().

        The remapped function is WinDivertOpen:

        HANDLE WinDivertOpen(
            __in const char *filter,
            __in WINDIVERT_LAYER layer,
            __in INT16 priority,
            __in UINT64 flags
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_open
        """
        self._handle = self._lib.WinDivertOpen(self._filter, self._layer, self._priority, self._flags)
        return self

    @winerror_on_retcode
    def recv(self, bufsize=Defaults.PACKET_BUFFER_SIZE):
        """
        Receives a diverted packet that matched the filter passed to the handle constructor.
        The return value is a pair (raw_packet, meta) where raw_packet is the data read by the handle, and meta contains
        the direction and interface indexes.
        The received packet is guaranteed to match the filter.

        The remapped function is WinDivertRecv:

        BOOL WinDivertRecv(
            __in HANDLE handle,
            __out PVOID pPacket,
            __in UINT packetLen,
            __out_opt PWINDIVERT_ADDRESS pAddr,
            __out_opt UINT *recvLen
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_recv
        """
        packet = create_string_buffer(bufsize)
        address = WinDivertAddress()
        recv_len = c_int(0)
        self._lib.WinDivertRecv(self._handle, packet, bufsize, byref(address), byref(recv_len))
        return packet[:recv_len.value], CapturedMetadata((address.IfIdx, address.SubIfIdx), address.Direction)


    @winerror_on_retcode
    def receive(self, bufsize=Defaults.PACKET_BUFFER_SIZE):
        """
        Receives a diverted packet that matched the filter passed to the handle constructor.
        The return value is an high level packet with right headers and payload parsed
        The received packet is guaranteed to match the filter.
        This is the low level way to access the driver.
        """
        return self.driver.parse_packet(self.recv(bufsize))

    def __parse_send_args(self, *args):
        """
        Utility method to parse arguments passed to send
        """
        if len(args) == 1:
            #Maybe this is a poor way to check the type, but it should work
            if hasattr(args[0], "__iter__") and not hasattr(args[0], "strip"):
                data, dest = args[0]
            elif isinstance(args[0], CapturedPacket):
                packet = self.driver.update_packet_checksums(args[0])
                data, dest = packet.raw, packet.meta
            else:
                raise ValueError("Not a CapturedPacket or sequence (data, meta): %s" % str(args))
        elif len(args) == 2:
            data, dest = args[0], args[1]
        else:
            raise ValueError("Wrong number of arguments passed to send")

        address = WinDivertAddress()
        address.IfIdx, address.SubIfIdx = dest.iface
        address.Direction = dest.direction
        return data, address

    @winerror_on_retcode
    def send(self, *args):
        """
        Injects a packet into the network stack.
        Args could be a tuple or two different values, or an high level packet. In each case the raw data and the meta
        about the direction and interface to use are required.
        If the packet is an highlevel packet, recalculates the checksum before sending.
        The return value is the number of bytes actually sent.

        The injected packet may be one received from receive(), or a modified version, or a completely new packet.
        Injected packets can be captured and diverted again by other WinDivert handles with lower priorities.

        The remapped function is DivertSend:

        BOOL WinDivertSend(
            __in HANDLE handle,
            __in PVOID pPacket,
            __in UINT packetLen,
            __in PWINDIVERT_ADDRESS pAddr,
            __out_opt UINT *sendLen
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_send
        """
        data, address = self.__parse_send_args(*args)
        send_len = c_int(0)
        self._lib.WinDivertSend(self._handle, data, len(data), byref(address), byref(send_len))
        return send_len

    #TODO: not ready method!
    def _receive_async(self, callback=None, bufsize=Defaults.PACKET_BUFFER_SIZE):
        """
        Receives a diverted packet that matched the filter passed to the handle constructor asynchronously.

        The remapped function is WinDivertRecvEx:

        BOOL WinDivertRecvEx(
            __in HANDLE handle,
            __out PVOID pPacket,
            __in UINT packetLen,
            __in UINT64 flags,
            __out_opt PWINDIVERT_ADDRESS pAddr,
            __out_opt UINT *recvLen,
            __inout_opt LPOVERLAPPED lpOverlapped
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_recv_ex
        """
        if not hasattr(self._lib, "WinDivertRecvEx"):
            raise MethodUnsupportedException("Async receive is not supported with this version of WinDivert")

        future = FuturePacket(self._handle, callback=callback, bufsize=bufsize)

        retcode = self._lib.WinDivertRecvEx(self._handle, byref(future.packet), sizeof(future.packet), 0,
                                            byref(future.address),
                                            byref(future.recv_len),
                                            byref(future.overlapped))
        last_error = GetLastError()
        if not retcode and last_error == ErrorCodes.ERROR_IO_PENDING:
            return future.get_result()
        else:
            raise AsyncCallFailedException(
                "Async receive failed with retcode %d and LastError %d" % (retcode, last_error))


    #TODO: not ready method!
    def _send_async(self, *args):
        """
        Injects a packet into the network stack.

        The remapped function is WinDivertSendEx:

        BOOL WinDivertSendEx(
            __in HANDLE handle,
            __in PVOID pPacket,
            __in UINT packetLen,
            __in UINT64 flags,
            __in PWINDIVERT_ADDRESS pAddr,
            __out_opt UINT *sendLen,
            __inout_opt LPOVERLAPPED lpOverlapped
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_send_ex
        """
        if not hasattr(self._lib, "WinDivertSendEx"):
            raise MethodUnsupportedException("Async send is not supported with this version of WinDivert")

        data, address = self.__parse_send_args(*args)
        send_len = len(data)
        retcode = self._lib.WinDivertSendEx(self._handle, data, send_len, 0, byref(address), None, None)

        last_error = GetLastError()
        if retcode and last_error == ErrorCodes.ERROR_IO_PENDING:
            return True
        else:
            raise AsyncCallFailedException("Async send failed with retcode %d and LastError %d" % (retcode, last_error))


            #yield wrapped(self)

    @winerror_on_retcode
    def close(self):
        """
        Closes the handle opened by open().

        The remapped function is:

        BOOL WinDivertClose(
            __in HANDLE handle
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_close
        """
        self._lib.WinDivertClose(self._handle)
        self._handle = None

    @property
    def is_opened(self):
        return self._handle is not None

    def get_param(self, name):
        """
        Gets a WinDivert parameter. See WinDivert DivertSetParam() for the list of parameters.

        The remapped function is DivertGetParam:

        BOOL WinDivertGetParam(
            __in HANDLE handle,
            __in WINDIVERT_PARAM param,
            __out UINT64 *pValue
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_get_param
        """
        value = c_uint64(0)
        self._lib.WinDivertGetParam(self._handle, name, byref(value))
        return value.value

    def set_param(self, name, value):
        """
        Sets a WinDivert parameter.

        The remapped function is DivertSetParam:

        BOOL WinDivertSetParam(
            __in HANDLE handle,
            __in WINDIVERT_PARAM param,
            __in UINT64 value
        );

        For more info on the C call visit: http://reqrypt.org/windivert-doc.html#divert_set_param
        """
        self._lib.WinDivertSetParam(self._handle, name, value)

    #Context Manager protocol
    def __enter__(self):
        return self.open()

    def __exit__(self, *args):
        self.close()
