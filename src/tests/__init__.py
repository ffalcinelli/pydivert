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

#SocketServer has been renamed in python3 to socketserver
import socket

try:
    from socketserver import ThreadingMixIn, TCPServer, UDPServer, BaseRequestHandler
except ImportError:
    from SocketServer import ThreadingMixIn, TCPServer, UDPServer, BaseRequestHandler


class EchoUpperTCPHandler(BaseRequestHandler):
    """
    Simple TCP request handler returning data to uppercase.
    """

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip()
        # just send back the same data, but upper-cased
        # print self.data
        self.request.sendall(self.data.upper())


class EchoUpperUDPHandler(BaseRequestHandler):
    """
    Simple UDP request handler returning data to uppercase.
    """

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        # print "{} wrote:".format(self.client_address[0])
        # print data
        socket.sendto(data.upper(), self.client_address)


class FakeTCPServerIPv4(ThreadingMixIn, TCPServer):
    allow_reuse_address = True

    def __str__(self):
        return "FakeTCPServerIPv4 listening on %s" % self.server_address


class FakeTCPServerIPv6(ThreadingMixIn, TCPServer):
    allow_reuse_address = True
    address_family = socket.AF_INET6

    def __str__(self):
        return "FakeTCPServerIPv6 listening on %s" % self.server_address


class FakeUDPServer(ThreadingMixIn, UDPServer):
    allow_reuse_address = True

    def __str__(self):
        return "FakeUDPServer listening on %s" % self.server_address


class FakeTCPClient():
    def __init__(self, connect_address, message, ipv6=False):
        self.connect_addr = connect_address
        self.message = message
        self.ipv6 = ipv6

    def send(self):
        sock = socket.socket(socket.AF_INET if not self.ipv6 else socket.AF_INET6, socket.SOCK_STREAM)
        sock.connect(self.connect_addr)
        try:
            sock.sendall(self.message)
            self.response = sock.recv(1024)
        finally:
            sock.close()


class FakeUDPClient():
    def __init__(self, connect_address, message, ipv6=False):
        self.connect_addr = connect_address
        self.message = message
        self.ipv6 = ipv6

    def send(self):
        sock = socket.socket(socket.AF_INET if not self.ipv6 else socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            sock.sendto(self.message, self.connect_addr)
            self.response = sock.recv(1024)
        finally:
            sock.close()


def get_free_port(ipv6=False, udp=False):
    import socket

    s = socket.socket(socket.AF_INET if not ipv6 else socket.AF_INET6,
                      socket.SOCK_STREAM if not udp else socket.SOCK_DGRAM)
    try:
        for p in range(1025, 65535):
            if s.connect_ex(('127.0.0.1' if not ipv6 else '::1', p)) == 0:
                return p
    finally:
        s.close()