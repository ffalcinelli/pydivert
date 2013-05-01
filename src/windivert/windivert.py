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
__author__ = 'fabio'

import ctypes
import os
from decorators import winerror_on_retcode
from winregistry import get_hklm_reg_values
from models import DivertAddress, DivertIpHeader, DivertIpv6Header, DivertIcmpHeader, DivertIcmpv6Header, DivertTcpHeader, DivertUdpHeader, CapturedPacket, CapturedMetadata
import enum


PACKET_BUFFER_SIZE = 4096


class WinDivert(object):
    """
    Python interface for WinDivert.dll library.
    """

    def __init__(self, dll_path=None, reg_key="SYSTEM\\CurrentControlSet\\Services\\WinDivert1.0"):
        if not dll_path:
            #We try to load from registry key
            self.registry = get_hklm_reg_values(reg_key)
            self.driver = self.registry["ImagePath"]
            dll_path = ("%s.%s" % (os.path.splitext(self.driver)[0], "dll"))[4:]
        self._lib = ctypes.CDLL(dll_path)

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
    def parse_packet(self, raw_packet):
        """
        Parses a raw packet into a higher level object.

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
        packet_len = len(raw_packet)
        payload = ctypes.c_void_p(0)
        payload_len = ctypes.c_uint(0)
        ip_hdr, ipv6_hdr = ctypes.pointer(DivertIpHeader()), ctypes.pointer(DivertIpv6Header())
        icmp_hdr, icmpv6_hdr = ctypes.pointer(DivertIcmpHeader()), ctypes.pointer(DivertIcmpv6Header())
        tcp_hdr, udp_hdr = ctypes.pointer(DivertTcpHeader()), ctypes.pointer(DivertUdpHeader())
        self._lib.DivertHelperParsePacket(raw_packet,
                                          packet_len,
                                          ctypes.byref(ip_hdr),
                                          ctypes.byref(ipv6_hdr),
                                          ctypes.byref(icmp_hdr),
                                          ctypes.byref(icmpv6_hdr),
                                          ctypes.byref(tcp_hdr),
                                          ctypes.byref(udp_hdr),
                                          ctypes.byref(payload),
                                          ctypes.byref(payload_len))

        # This works as well as reading the pointed location.
        # So far, we use that way
        # if payload_len:
        #     payload = packet[payload_len.value * -1:]

        captured = CapturedPacket(content=ctypes.string_at(payload.value) if payload else "", raw_packet=raw_packet)
        #captured = CapturedPacket(contents=payload if payload else None)
        for hdr in (ip_hdr, ipv6_hdr, icmp_hdr, icmpv6_hdr):
            if hdr:
                captured.set_network_header(hdr.contents)
        for hdr in (tcp_hdr, udp_hdr):
            if hdr:
                captured.set_transport_header(hdr.contents)
        return captured

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
        buff_pointer = ctypes.pointer(ctypes.create_string_buffer(packet))
        self._lib.DivertHelperCalcChecksums(ctypes.byref(buff_pointer), packet_len, flags)
        #TODO: check the reason why there's a 0 at the end
        return buff_pointer.contents[:-1]

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
    def receive(self):
        """
        Receives a diverted packet that matched the filter passed to the handle constructor.
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
        packet = ctypes.create_string_buffer(PACKET_BUFFER_SIZE)
        address = DivertAddress()
        recv_len = ctypes.c_int(0)
        self._lib.DivertRecv(self._handle, packet, PACKET_BUFFER_SIZE, ctypes.byref(address), ctypes.byref(recv_len))
        return packet[:recv_len.value], CapturedMetadata((address.IfIdx, address.SubIfIdx), address.Direction)

    @winerror_on_retcode
    def send(self, (data, dest)):
        """
        Injects a packet into the network stack.
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
        Closes a WinDivert handle opened by open().

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


# if __name__ == "__main__":
#     current_dir = os.path.join(os.path.dirname(__file__), os.pardir, "../lib")
#     os.chdir(current_dir)
#     windivert = WinDivert(os.path.join(current_dir, "WinDivert.dll"))
#     with Handle(windivert, filter="tcp.DstPort == 23", priority=1000) as filter1:
#         while True:
#             raw_packet, meta = filter1.receive()
#             captured_packet = windivert.parse_packet(raw_packet)
#             print captured_packet
#             filter1.send((raw_packet, meta))