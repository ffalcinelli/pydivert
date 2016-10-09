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
import itertools
import socket
import threading
import time

import pytest
from pydivert.consts import Param
from pydivert.windivert import WinDivert

try:
    # SocketServer has been renamed in python3 to socketserver
    from socketserver import ThreadingMixIn, TCPServer, UDPServer, BaseRequestHandler
    from queue import Queue
except ImportError:
    from SocketServer import ThreadingMixIn, TCPServer, UDPServer, BaseRequestHandler
    from Queue import Queue


@pytest.fixture
def w():
    with WinDivert("false") as w:
        yield w


@pytest.fixture(params=list(itertools.product(
    ("ipv4", "ipv6"),
    ("tcp", "udp"),
)), ids=lambda x: ",".join(x))
def scenario(request):
    ip_version, proto = request.param

    """
    if proto == socket.IPPROTO_TCP:
        ServerBase = TCPServer
        Handler = EchoUpperTCPHandler
    else:
        ServerBase = UDPServer
        Handler = EchoUpperUDPHandler
    class Server(ThreadingMixIn, ServerBase):
        address_family = atype

    server = Server((host, 0), Handler)
    """

    if ip_version == "ipv4":
        atype = socket.AF_INET
        host = "127.0.0.1"
    else:
        atype = socket.AF_INET6
        host = "::1"
    if proto == "tcp":
        stype = socket.SOCK_STREAM
    else:
        stype = socket.SOCK_DGRAM

    server = socket.socket(atype, stype)
    server.bind((host, 0))
    client = socket.socket(atype, stype)
    client.bind((host, 0))

    reply = Queue()

    if proto == "tcp":
        def server_echo():
            server.listen(1)
            conn, addr = server.accept()
            conn.sendall(conn.recv(4096).upper())
            conn.close()

        def send(addr, data):
            client.connect(addr)
            client.sendall(data)
            reply.put(client.recv(4096))
    else:
        def server_echo():
            data, addr = server.recvfrom(4096)
            server.sendto(data.upper(), addr)

        def send(addr, data):
            client.sendto(data, addr)
            data, recv_addr = client.recvfrom(4096)
            assert addr[:2] == recv_addr[:2]  # only accept responses from the same host
            reply.put(data)

    server_thread = threading.Thread(target=server_echo)
    server_thread.start()

    filt = "{proto}.SrcPort == {c_port} or {proto}.SrcPort == {s_port}".format(
        proto=proto,
        c_port=client.getsockname()[1],
        s_port=server.getsockname()[1]
    )

    def send_thread(*args, **kwargs):
        threading.Thread(target=send, args=args, kwargs=kwargs).start()
        return reply

    with WinDivert(filt) as w:
        yield client.getsockname(), server.getsockname(), w, send_thread
    client.close()
    server.close()


def test_open():
    w = WinDivert("false")
    w.open()
    assert w.is_open
    w.close()
    assert not w.is_open

    with w:
        # open a second one.
        with WinDivert("false") as w2:
            assert w2.is_open

        assert w.is_open
        assert "open" in repr(w)

    assert not w.is_open
    assert "closed" in repr(w)


@pytest.mark.timeout(5)
def test_register():
    if WinDivert.is_registered():
        WinDivert.unregister()
    while WinDivert.is_registered():
        time.sleep(0.01)  # pragma: no cover
    assert not WinDivert.is_registered()
    WinDivert.register()
    assert WinDivert.is_registered()


@pytest.mark.timeout(5)
def test_unregister():
    w = WinDivert("false")
    w.open()
    WinDivert.unregister()
    time.sleep(0.1)
    assert WinDivert.is_registered()
    w.close()
    # may not trigger immediately.
    while WinDivert.is_registered():
        time.sleep(0.01)  # pragma: no cover


class TestParams(object):
    def test_queue_time_range(self, w):
        """
        Tests setting the minimum value for queue time.
        From docs: 128 < default 512 < 2048
        """
        def_range = (128, 512, 2048)
        for value in def_range:
            w.set_param(Param.QUEUE_TIME, value)
            assert value == w.get_param(Param.QUEUE_TIME)

    def test_queue_len_range(self, w):
        """
        Tests setting the minimum value for queue length.
        From docs: 1< default 512 <8192
        """
        for value in (1, 512, 8192):
            w.set_param(Param.QUEUE_LEN, value)
            assert value == w.get_param(Param.QUEUE_LEN)

    def test_invalid_set(self, w):
        with pytest.raises(Exception):
            w.set_param(42, 43)

    def test_invalid_get(self, w):
        with pytest.raises(Exception):
            w.get_param(42)


def test_echo(scenario):
    client_addr, server_addr, w, send = scenario
    w = w  # type: WinDivert
    reply = send(server_addr, b"echo")

    for p in w:
        assert p.is_loopback
        assert p.is_outbound
        w.send(p)
        done = (
            (p.is_udp and p.dst_port == client_addr[1])
            or
            (p.is_tcp and p.tcp_fin)
        )
        if done:
            break

    assert reply.get() == b"ECHO"


def test_divert(scenario):
    client_addr, server_addr, w, send = scenario
    w = w  # type: WinDivert
    target = (server_addr[0], 80)
    reply = send(target, b"echo")
    for p in w:
        if p.src_port == client_addr[1]:
            p.dst_port = server_addr[1]
        if p.src_port == server_addr[1]:
            p.src_port = target[1]
        w.send(p)

        done = (
            (p.is_udp and p.dst_port == client_addr[1])
            or
            (p.is_tcp and p.tcp_fin)
        )
        if done:
            break

    assert reply.get() == b"ECHO"


def test_modify_payload(scenario):
    client_addr, server_addr, w, send = scenario
    w = w  # type: WinDivert
    reply = send(server_addr, b"echo")

    for p in w:
        p.payload = p.payload.replace(b"echo", b"test").replace(b"TEST", b"ECHO")
        w.send(p)

        done = (
            (p.is_udp and p.dst_port == client_addr[1])
            or
            (p.is_tcp and p.tcp_fin)
        )
        if done:
            break
    assert reply.get() == b"ECHO"


def test_packet_cutoff(scenario):
    client_addr, server_addr, w, send = scenario
    w = w  # type: WinDivert
    reply = send(server_addr, b"a" * 1000)

    cutoff = None
    while True:
        p = w.recv(500)
        if p.ip_packet_len != len(p.raw):
            assert cutoff is None
            cutoff = p.ip_packet_len - len(p.raw)
            p.payload = p.payload  # fix length
        w.send(p)
        done = (
            (p.is_udp and p.dst_port == client_addr[1])
            or
            (p.is_tcp and p.tcp_fin)
        )
        if done:
            break
    assert cutoff
    assert reply.get() == b"A" * (1000 - cutoff)
