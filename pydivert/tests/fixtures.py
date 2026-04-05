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

import itertools
import socket
import threading

import pytest

import pydivert

from queue import Queue


@pytest.fixture
def windivert_handle():
    with pydivert.WinDivert("false") as w:
        yield w


@pytest.fixture(
    params=list(
        itertools.product(
            ("ipv4", "ipv6"),
            ("tcp", "udp"),
        )
    ),
    ids=lambda x: ",".join(x),
)
def scenario(request):
    ip_version, proto = request.param

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

    with socket.socket(atype, stype) as server, socket.socket(atype, stype) as client:
        server.bind((host, 0))
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

        filt = f"{proto}.SrcPort == {client.getsockname()[1]} or {proto}.SrcPort == {server.getsockname()[1]}"

        def send_thread(*args, **kwargs):
            threading.Thread(target=send, args=args, kwargs=kwargs).start()
            return reply

        with pydivert.WinDivert(filt) as w:
            yield client.getsockname(), server.getsockname(), w, send_thread
