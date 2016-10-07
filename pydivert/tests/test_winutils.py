# -*- coding: utf-8 -*-
# Copyright (C) 2016  Fabio Falcinelli
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
import socket
import unittest

import pytest
from pydivert.winutils import addr_to_string, string_to_addr

__author__ = 'fabio'


class WinInetTestCase(unittest.TestCase):

    def test_ipv4_loopback_conversion(self):
        """
        Tests IPv4 loopback address conversions
        """
        address = "127.0.0.1"
        addr_fam = socket.AF_INET
        assert address == addr_to_string(addr_fam, string_to_addr(addr_fam, address))

    def test_ipv6_loopback_conversion(self):
        """
        Tests IPv6 loopback address conversions
        """
        address = "::1"
        addr_fam = socket.AF_INET6
        ipv6 = addr_to_string(addr_fam, string_to_addr(addr_fam, address))
        assert ipv6 in "::1"

    def test_ipv4_address_conversion(self):
        """
        Tests IPv4 address conversions
        """
        address = "192.168.1.1"
        addr_fam = socket.AF_INET
        assert address == addr_to_string(addr_fam, string_to_addr(addr_fam, address))

    def test_ipv6_address_conversion(self):
        """
        Tests IPv6 address conversions
        """
        address = "2607:f0d0:1002:0051:0000:0000:0000:0004"
        addr_fam = socket.AF_INET6
        ipv6 = addr_to_string(addr_fam, string_to_addr(addr_fam, address))
        assert ipv6 in (address, "2607:f0d0:1002:51::4")

    def test_ipv4_wrong_address_family(self):
        """
        Tests IPv4 address conversions
        """
        address = "192.168.1.1"
        addr_fam = -1
        with pytest.raises(ValueError):
            string_to_addr(addr_fam, address)
        addr = string_to_addr(socket.AF_INET, address)
        with pytest.raises(ValueError):
            addr_to_string(addr_fam, (addr,))

    def test_ipv6_wrong_address_family(self):
        """
        Tests IPv6 address conversions
        """
        address = "2607:f0d0:1002:0051:0000:0000:0000:0004"
        addr_fam = -1
        with pytest.raises(ValueError):
            string_to_addr(addr_fam, address)
        addr = string_to_addr(socket.AF_INET6, address)
        with pytest.raises(ValueError):
            addr_to_string(addr_fam, addr)
