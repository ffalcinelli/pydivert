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
import socket
import struct
from windivert import enum
from windivert.win_inet_pton import inet_pton

__author__ = 'fabio'

import threading
from tests import FakeTCPServer, EchoUpperTCPRequestHandler, FakeTCPClient
import unittest
import os
import platform
from windivert.enum import DIVERT_PARAM_QUEUE_LEN, DIVERT_PARAM_QUEUE_TIME
from windivert.winregistry import get_hklm_reg_values
from windivert.windivert import Handle, WinDivert


driver_dir = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "lib")
if platform.architecture()[0] == "32bit":
    driver_dir = os.path.join(driver_dir, "x86")
else:
    driver_dir = os.path.join(driver_dir, "amd64")


class WinDivertTestCase(unittest.TestCase):
    """
    Tests the driver registration, opening handles and functions not requiring network traffic
    """

    def setUp(self):
        os.chdir(driver_dir)
        self.dll_path = os.path.join(driver_dir, "WinDivert.dll")

    # def test_insufficient_privileges(self):
    #     self.assertRaises(WindowsError, WinDivert.load_library, self.dll_path)

    def test_load_ok(self):
        """
        Test DLL loading with a correct path
        """
        try:
            WinDivert(self.dll_path)
        except WindowsError as e:
            self.fail("WinDivert() constructor raised %s" % e)

    def test_load_invalid_path(self):
        """
        Test DLL loading with an invalid path
        """
        self.assertRaises(WindowsError, WinDivert, "invalid_path")

    def test_open_handle(self):
        """
        Test the open_handle method.
        """
        handle = WinDivert(self.dll_path).open_handle(filter="tcp.DstPort == 23", priority=1000)
        self.assertIsInstance(handle, Handle)
        self.assertTrue(handle.is_opened)
        handle.close()
        self.assertFalse(handle.is_opened)

    def test_load_from_registry(self):
        """
        Test WinDivert loading from registry key. This assumes the driver has been
        previously registered
        """
        try:
            reg_key = "SYSTEM\\CurrentControlSet\\Services\\WinDivert1.0"
            if get_hklm_reg_values(reg_key):
                WinDivert(reg_key=reg_key)
        except WindowsError as e:
            self.fail("WinDivert() constructor raised %s" % e)

    def test_construct_handle(self):
        """
        Test constructing an handle from a WinDivert instance
        """
        driver = WinDivert()
        handle = Handle(driver, filter="tcp.DstPort == 23", priority=1000)
        self.assertIsInstance(handle, Handle)
        self.assertFalse(handle.is_opened)

    def test_implicit_construct_handle(self):
        """
        Test constructing an handle without passing a WinDivert instance
        """
        handle = Handle(filter="tcp.DstPort == 23", priority=1000)
        self.assertIsInstance(handle, Handle)
        self.assertFalse(handle.is_opened)


    def test_handle_invalid(self):
        """
        Test constructing an handle from a WinDivert instance
        """
        handle = Handle(filter="tcp.DstPort == 23", priority=1000)
        #The handle is not opened so we expect an error
        self.assertRaises(WindowsError, handle.close)

    def test_context_manager(self):
        """
        Test usage of an Handle as a context manager
        """
        with Handle(filter="tcp.DstPort == 23", priority=1000) as filter0:
            self.assertNotEqual(str(filter0._handle), "-1")

    def test_getter_and_setter(self):
        """
        Test getting and setting params to windivert
        """
        queue_len = 2048
        queue_time = 64
        with Handle(filter="tcp.DstPort == 23", priority=1000) as filter0:
            filter0.set_param(DIVERT_PARAM_QUEUE_LEN, queue_len)
            self.assertEqual(queue_len, filter0.get_param(DIVERT_PARAM_QUEUE_LEN))
            filter0.set_param(DIVERT_PARAM_QUEUE_TIME, queue_time)
            self.assertEqual(queue_time, filter0.get_param(DIVERT_PARAM_QUEUE_TIME))

    def test_parse_ipv4_address(self):
        """
        Test parsing of an ipv4 address into a network byte value
        """
        address = "192.168.1.1"
        result = WinDivert().parse_ipv4_address(address)
        self.assertEqual(struct.unpack(">I", inet_pton(socket.AF_INET, address))[0], result)

    def test_parse_ipv6_address(self):
        """
        Test parsing of an ipv4 address into a network byte value
        """
        address = "2607:f0d0:1002:0051:0000:0000:0000:0004"
        result = WinDivert().parse_ipv6_address(address)
        self.assertEqual(struct.unpack("<HHHHHHHH", inet_pton(socket.AF_INET6, address)), tuple(result))

    def tearDown(self):
        pass


class WinDivertTCPCaptureTestCase(unittest.TestCase):
    """
    Tests capturing TCP traffic with payload
    """

    def setUp(self):
        os.chdir(driver_dir)
        # Initialize the fake tcp server
        self.server = FakeTCPServer((socket.gethostbyname(socket.gethostname()), 0), EchoUpperTCPRequestHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()

        # Initialize the fake tcp client
        self.text = "Hello World!"
        self.client = FakeTCPClient(self.server.server_address, self.text)
        self.client_thread = threading.Thread(target=self.client.send)

    # def test_pass_through_no_payload(self):
    #     """
    #     Test capturing everything make pass our request
    #     """
    #     with Handle(filter="tcp.DstPort == %s" % self.server.server_address[1]) as handle:
    #         self.client_thread.start()
    #         packet = None
    #         while True:
    #             raw_packet, meta = handle.receive()
    #             packet = handle.driver.parse_packet(raw_packet)
    #             if self.text in packet.payload:
    #                 handle.send((raw_packet, meta))
    #                 break
    #             handle.send((raw_packet, meta))
    #         self.client_thread.join(timeout=10)
    #         self.assertEqual(self.text.upper(), self.client.response)


    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()


class WinDivertTCPCapturePayloadTestCase(unittest.TestCase):
    """
    Tests capturing TCP traffic with payload
    """

    def setUp(self):
        os.chdir(driver_dir)
        # Initialize the fake tcp server
        self.server = FakeTCPServer(("localhost", 0), EchoUpperTCPRequestHandler)
        filter = "outbound and tcp.DstPort == %d and tcp.PayloadLength > 0" % self.server.server_address[1]
        self.driver = WinDivert(os.path.join(driver_dir, "WinDivert.dll"))
        self.handle = self.driver.open_handle(filter=filter)

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()

        # Initialize the fake tcp client
        self.text = "Hello World!"
        self.client = FakeTCPClient(self.server.server_address, self.text)
        self.client_thread = threading.Thread(target=self.client.send)
        self.client_thread.start()

    def test_packet_metadata(self):
        """
        Test if metadata is right
        """
        raw_packet, metadata = self.handle.receive()
        self.assertEqual(metadata.direction, 0)  # 0 is for outbound

    def test_pass_through(self):
        """
        Test receiving and resending data
        """
        self.handle.send(self.handle.receive())
        self.client_thread.join(timeout=10)
        self.assertEqual(self.text.upper(), self.client.response)

    def test_parse_packet(self):
        """
        Test parsing packets to intercept the payload
        """
        raw_packet, metadata = self.handle.receive()
        packet = self.driver.parse_packet(raw_packet)
        self.assertEqual("%s:%d" % (packet.dst_addr, packet.dst_port),
                         "%s:%d" % self.server.server_address)
        self.assertEqual(self.text, packet.payload)

    def test_dump_data(self):
        """
        Test receiving, print and resending data
        """
        raw_packet, metadata = self.handle.receive()
        packet = self.handle.driver.parse_packet(raw_packet)
        self.assertIn(raw_packet[len(packet.payload)*-1:], str(packet))
        self.handle.send((raw_packet, metadata))
        self.client_thread.join(timeout=10)
        self.assertEqual(self.text.upper(), self.client.response)

    def test_raw_packet_from_captured(self):
        """
        Test reconstructing raw packet from a captured one
        """
        raw_packet1, metadata = self.handle.receive()
        packet = self.handle.driver.parse_packet(raw_packet1)
        raw_packet2 = packet.to_raw_packet()
        self.assertEqual(hexlify(raw_packet1), hexlify(raw_packet2))

    def test_packet_checksum(self):
        """
        Test checksum without changes
        """
        raw_packet1, metadata = self.handle.receive()
        raw_packet2 = self.handle.driver.calc_checksums(raw_packet1)
        self.assertEqual(hexlify(raw_packet1), hexlify(raw_packet2))

    def tearDown(self):
        self.handle.close()
        self.server.shutdown()
        self.server.server_close()


class WinDivertTCPInjectTestCase(unittest.TestCase):
    """
    Tests on the fly capturing and injecting TCP traffic
    """

    def setUp(self):
        os.chdir(driver_dir)
        # Initialize the fake tcp server
        self.server = FakeTCPServer(("127.0.0.1", 0), EchoUpperTCPRequestHandler)
        self.driver = WinDivert(os.path.join(driver_dir, "WinDivert.dll"))

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()

    def test_packet_injection(self):
        """
        Test injection of a modified packet
        """
        with Handle(filter="outbound and tcp.DstPort == %s and tcp.PayloadLength>0" % self.server.server_address[1]) as handle:
            self.text = "Hello world! ZZZZ"
            self.new_text = "Hello World!"
            # Initialize the fake tcp client
            self.client = FakeTCPClient(("127.0.0.1", self.server.server_address[1]), self.text)
            self.client_thread = threading.Thread(target=self.client.send)
            self.client_thread.start()

            raw_packet, metadata = handle.receive()
            if metadata.direction == enum.DIVERT_DIRECTION_OUTBOUND:
                packet = handle.driver.parse_packet(raw_packet)
                self.assertEqual(self.text, packet.payload)
                packet.payload = self.new_text
                raw_packet = packet.to_raw_packet()

            handle.send((raw_packet, metadata))
            self.client_thread.join(timeout=10)
            self.assertEqual(self.new_text.upper(), self.client.response)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

if __name__ == '__main__':
    unittest.main()