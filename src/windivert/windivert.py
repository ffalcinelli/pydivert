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
from binascii import hexlify

__author__ = 'fabio'

import ctypes
import os
from decorators import winerror_on_retcode
from winregistry import get_reg_values
from models import DivertAddress, DivertIpHeader, DivertIpv6Header, DivertIcmpHeader, DivertIcmpv6Header, DivertTcpHeader, DivertUdpHeader, CapturedPacket, CapturedMetadata, HeaderWrapper
import enum


PACKET_BUFFER_SIZE = 4096


class WinDivert(object):
    """
    Python interface for WinDivert.dll library.
    """

    def __init__(self, dll_path=None, reg_key=r"SYSTEM\CurrentControlSet\Services\WinDivert1.0"):
        if not dll_path:
            #We try to load from registry key
            self.registry = get_reg_values(reg_key)
            self.driver = self.registry["ImagePath"]
            dll_path = ("%s.%s" % (os.path.splitext(self.driver)[0], "dll"))[4:]
        self._lib = ctypes.CDLL(dll_path)
        self.reg_key = reg_key

    def open_handle(self, filter="true", layer=enum.DIVERT_LAYER_NETWORK, priority=0, flags=0):
        """
        Return a new handle already opened
        """
        return Handle(self, filter, layer, priority, flags).open()

    def get_reference(self):
        """
        Return a reference to the internal CDLL
        """
        return self._lib

    @winerror_on_retcode
    def parse_packet(self, *args):
        """
        Parses a raw packet into a higher level object.
        Args could be a tuple or two different values. In each case the first one is the raw data and the second
        is the meta about the direction and interface to use.

        The function remapped is DivertHelperParsePacket:
        Parses a raw packet (e.g. from DivertRecv()) into the various packet headers
        and/or payloads that may or may not be present.

        BOOL DivertHelperParsePacket(
            __in PVOID pPacket,
            __in UINT packetLen,
            __out_opt PDIVERT_IPHDR *ppIpHdr,
            __out_opt PDIVERT_IPV6HDR *ppIpv6Hdr,
            __out_opt PDIVERT_ICMPHDR *ppIcmpHdr,
            __out_opt PDIVERT_ICMPV6HDR *ppIcmpv6Hdr,
            __out_opt PDIVERT_TCPHDR *ppTcpHdr,
            __out_opt PDIVERT_UDPHDR *ppUdpHdr,
            __out_opt PVOID *ppData,
            __out_opt UINT *pDataLen
        );
        """
        if len(args) == 1:
            if hasattr(args[0], "__iter__"):
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
        payload_len = ctypes.c_uint(0)
        ip_hdr, ipv6_hdr = ctypes.pointer(DivertIpHeader()), ctypes.pointer(DivertIpv6Header())
        icmp_hdr, icmpv6_hdr = ctypes.pointer(DivertIcmpHeader()), ctypes.pointer(DivertIcmpv6Header())
        tcp_hdr, udp_hdr = ctypes.pointer(DivertTcpHeader()), ctypes.pointer(DivertUdpHeader())
        headers = (ip_hdr, ipv6_hdr, icmp_hdr, icmpv6_hdr, tcp_hdr, udp_hdr)
        self._lib.DivertHelperParsePacket(raw_packet,
                                          packet_len,
                                          ctypes.byref(ip_hdr),
                                          ctypes.byref(ipv6_hdr),
                                          ctypes.byref(icmp_hdr),
                                          ctypes.byref(icmpv6_hdr),
                                          ctypes.byref(tcp_hdr),
                                          ctypes.byref(udp_hdr),
                                          None,
                                          ctypes.byref(payload_len))
        #headers_len = sum(ctypes.sizeof(hdr.contents) for hdr in headers if hdr)
        #headers_len = sum((getattr(hdr.contents, "HdrLength", 0) * 4) for hdr in headers if hdr)

        # clean headers, consider just those that are not None (!=NULL)
        headers = [hdr.contents for hdr in headers if hdr]

        headers_opts = []
        offset = 0
        for header in headers:
            if hasattr(header, "HdrLength"):
                header_len = getattr(header, "HdrLength", 0) * 4
                opt_len = header_len - ctypes.sizeof(header)
                if opt_len:
                    opt = raw_packet[offset + header_len - opt_len:offset + header_len]
                    headers_opts.append(opt)
                else:
                    headers_opts.append('')
            else:
                headers_opts.append('')
                header_len = ctypes.sizeof(header)
            offset += header_len

        return CapturedPacket(payload=raw_packet[offset:],
                              raw_packet=raw_packet,
                              headers=[HeaderWrapper(hdr, opt) for hdr, opt in zip(headers, headers_opts)],
                              meta=meta)

    @winerror_on_retcode
    def parse_ipv4_address(self, address):
        """
        Parses an IPv4 address.

        The function remapped is DivertHelperParseIPv4Address:
        BOOL DivertHelperParseIPv4Address(
            __in const char *addrStr,
            __out_opt UINT32 *pAddr
        );
        """
        ip_addr = ctypes.c_uint32(0)
        self._lib.DivertHelperParseIPv4Address(address, ctypes.byref(ip_addr))
        return ip_addr.value


    @winerror_on_retcode
    def parse_ipv6_address(self, address):
        """
        Parses an IPv6 address.

        The function remapped is DivertHelperParseIPv4Address:
        BOOL DivertHelperParseIPv6Address(
            __in const char *addrStr,
            __out_opt UINT32 *pAddr
        );
        """
        ip_addr = ctypes.ARRAY(ctypes.c_uint16, 8)()
        self._lib.DivertHelperParseIPv6Address(address, ctypes.byref(ip_addr))
        return [x for x in ip_addr]

    @winerror_on_retcode
    def calc_checksums(self, packet, flags=0):
        """
        (Re)calculates the checksum for any IPv4/ICMP/ICMPv6/TCP/UDP checksum present in the given packet.
        Individual checksum calculations may be disabled via the appropriate flag.
        Typically this function should be invoked on a modified packet before it is injected with send().

        The function remapped is DivertHelperCalcChecksums:
        UINT DivertHelperCalcChecksums(
            __inout PVOID pPacket,
            __in UINT packetLen,
            __in UINT64 flags
        );
        """
        packet_len = len(packet)
        buff = ctypes.create_string_buffer(packet, packet_len)
        self._lib.DivertHelperCalcChecksums(ctypes.byref(buff), packet_len, flags)
        return buff

    @winerror_on_retcode
    def update_packet_checksums(self, packet):
        """
        An utility shortcut method to update the checksums into an higher level packet
        """
        raw = self.calc_checksums(packet.raw_packet)
        return self.parse_packet(raw, packet.meta)

    @winerror_on_retcode
    def register(self):
        """
        An utility method to register the driver the first time
        """
        handle = self.open_handle("false")
        handle.close()

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

    def __init__(self, driver=None, filter="true", layer=enum.DIVERT_LAYER_NETWORK, priority=0, flags=0):
        if not driver:
            #Try to construct by loading from the registry
            self.driver = WinDivert()
        else:
            self.driver = driver
        self._lib = self.driver.get_reference()
        self._handle = None
        self._filter = filter
        self._layer = layer
        self._priority = priority
        self._flags = flags

    @winerror_on_retcode
    def open(self):
        """
        Opens a WinDivert handle for the given filter.
        Unless otherwise specified by flags, any packet that matches the filter will be diverted to the handle.
        Diverted packets can be read by the application with receive().

        The remapped function is DivertOpen:
        HANDLE DivertOpen(
            __in const char *filter,
            __in DIVERT_LAYER layer,
            __in INT16 priority,
            __in UINT64 flags
        );
        """
        self._handle = self._lib.DivertOpen(self._filter, self._layer, self._priority, self._flags)
        return self

    @winerror_on_retcode
    def recv(self, bufsize=PACKET_BUFFER_SIZE):
        """
        Receives a diverted packet that matched the filter passed to the handle constructor.
        The return value is a pair (raw_packet, meta) where raw_packet is the data read by the handle, and meta contains
        the direction and interface indexes.
        The received packet is guaranteed to match the filter.

        The remapped function is DivertRecv:
        BOOL DivertRecv(
            __in HANDLE handle,
            __out PVOID pPacket,
            __in UINT packetLen,
            __out_opt PDIVERT_ADDRESS pAddr,
            __out_opt UINT *recvLen
        );
        """
        packet = ctypes.create_string_buffer(bufsize)
        address = DivertAddress()
        recv_len = ctypes.c_int(0)
        self._lib.DivertRecv(self._handle, packet, bufsize, ctypes.byref(address), ctypes.byref(recv_len))
        print("RECVLEN {}/{}".format(recv_len, len(packet)))
        print("".join([x for x in packet]))
        return packet[:recv_len.value], CapturedMetadata((address.IfIdx, address.SubIfIdx), address.Direction)

    @winerror_on_retcode
    def receive(self, bufsize=PACKET_BUFFER_SIZE):
        """
        Receives a diverted packet that matched the filter passed to the handle constructor.
        The return value is an high level packet with right headers and payload parsed
        The received packet is guaranteed to match the filter.
        This is the low level way to access the driver.
        """
        return self.driver.parse_packet(self.recv(bufsize))

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
        BOOL DivertSend(
            __in HANDLE handle,
            __in PVOID pPacket,
            __in UINT packetLen,
            __in PDIVERT_ADDRESS pAddr,
            __out_opt UINT *sendLen
        );
        """
        if len(args) == 1:
            if hasattr(args[0], "__iter__"):
                data, dest = args[0]
            else:
                packet = self.driver.update_packet_checksums(args[0])
                data, dest = packet.raw_packet, packet.meta
        elif len(args) == 2:
            data, dest = args[0], args[1]
        else:
            raise ValueError("Wrong number of arguments passed to send")

        address = DivertAddress()
        address.IfIdx = dest.iface[0]
        address.SubIfIdx = dest.iface[1]
        address.Direction = dest.direction
        send_len = ctypes.c_int(0)

        self._lib.DivertSend(self._handle, data, len(data), ctypes.byref(address), ctypes.byref(send_len))
        return send_len

    @winerror_on_retcode
    def close(self):
        """
        Closes the handle opened by open().

        The remapped function is:
        BOOL DivertClose(
            __in HANDLE handle
        );
        """
        self._lib.DivertClose(self._handle)
        self._handle = None

    @property
    def is_opened(self):
        return self._handle is not None

    def get_param(self, name):
        """
        Gets a WinDivert parameter. See WinDivert DivertSetParam() for the list of parameters.

        The remapped function is DivertGetParam:
        BOOL DivertGetParam(
            __in HANDLE handle,
            __in DIVERT_PARAM param,
            __out UINT64 *pValue
        );
        """
        value = ctypes.c_uint64(0)
        self._lib.DivertGetParam(self._handle, name, ctypes.byref(value))
        return value.value

    def set_param(self, name, value):
        """
        Sets a WinDivert parameter.

        The remapped function is DivertSetParam:
        BOOL DivertSetParam(
            __in HANDLE handle,
            __in DIVERT_PARAM param,
            __in UINT64 value
        );
        """
        self._lib.DivertSetParam(self._handle, name, value)

    #Context Manager protocol
    def __enter__(self):
        return self.open()

    def __exit__(self, *args):
        self.close()


if __name__ == "__main__":
    driver_dir = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "lib")
    import platform

    if platform.architecture()[0] == "32bit":
        driver_dir = os.path.join(driver_dir, "x86")
    else:
        driver_dir = os.path.join(driver_dir, "amd64")
    os.chdir(driver_dir)
    driver = WinDivert(os.path.join(driver_dir, "WinDivert.dll"))
    with Handle(driver, filter="tcp.DstPort == 3128 or tcp.SrcPort == 3128", priority=1000) as filter1:
        dest_address = None
        while True:
            print("-----ROUND-----")
            raw_packet, meta = filter1.recv()
            packet = filter1.driver.parse_packet(raw_packet, meta)
            print(packet)
            filter1.send(packet.raw_packet, packet.meta)