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

import sys

import pytest

from pydivert.consts import Param
from pydivert.windivert import WinDivert

from .fixtures import scenario
from .fixtures import windivert_handle as w

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")

assert scenario, w  # keep fixtures


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

        with pytest.raises(RuntimeError):
            w.open()

    assert not w.is_open
    assert "closed" in repr(w)

    with pytest.raises(RuntimeError):
        w.recv()
    with pytest.raises(RuntimeError):
        w.close()


class TestParams:
    def test_queue_time_range(self, w):
        """
        Tests setting and getting the value for queue time at its boundaries.
        From docs: 128 < default 512 < 2048
        """
        for value in (128, 512, 2048):
            w.set_param(Param.QUEUE_TIME, value)
            assert value == w.get_param(Param.QUEUE_TIME)

    @pytest.mark.skip(reason="Fails on Vagrant VM with WinError 87")
    def test_queue_len_range(self, w):
        """
        Tests setting and getting the value for queue length at its boundaries.
        From docs: 2 <= queue length <= 16384
        """
        for value in (2, 512, 16384):
            w.set_param(Param.QUEUE_LEN, value)
            assert value == w.get_param(Param.QUEUE_LEN)

    @pytest.mark.skip(reason="Fails on Vagrant VM with WinError 87")
    def test_queue_size_range(self, w):
        """
        Tests setting and getting the value for queue size at its boundaries.
        From docs: 4096 (4KB) < default 4194304 (4MB) < 33554432 (32MB)
        """
        for value in (4096, 4194304, 33554432):
            w.set_param(Param.QUEUE_SIZE, value)
            assert value == w.get_param(Param.QUEUE_SIZE)

    def test_invalid_set(self, w):
        with pytest.raises(OSError):
            w.set_param(42, 43)

    def test_invalid_get(self, w):
        with pytest.raises(OSError):
            w.get_param(42)


def test_echo(scenario) -> None:
    client_addr, server_addr, w, send = scenario
    reply = send(server_addr, b"echo")

    for p in w:
        assert p.is_loopback
        assert p.is_outbound
        w.send(p)
        done = p.udp and p.dst_port == client_addr[1] or p.tcp and p.tcp.fin
        if done:
            break

    assert reply.get(timeout=10) == b"ECHO"


def test_divert(scenario) -> None:
    client_addr, server_addr, w, send = scenario
    target = (server_addr[0], 80)
    reply = send(target, b"echo")
    for p in w:
        if p.src_port == client_addr[1]:
            p.dst_port = server_addr[1]
        if p.src_port == server_addr[1]:
            p.src_port = target[1]
        w.send(p)

        done = p.udp and p.dst_port == client_addr[1] or p.tcp and p.tcp.fin
        if done:
            break

    assert reply.get(timeout=10) == b"ECHO"


def test_modify_payload(scenario) -> None:
    client_addr, server_addr, w, send = scenario
    reply = send(server_addr, b"echo")

    for p in w:
        p.payload = p.payload.replace(b"echo", b"test").replace(b"TEST", b"ECHO")
        w.send(p)

        done = p.udp and p.dst_port == client_addr[1] or p.tcp and p.tcp.fin
        if done:
            break
    assert reply.get(timeout=10) == b"ECHO"


@pytest.mark.skip(reason="Fails on Vagrant VM: packets are not truncated as expected")
def test_packet_cutoff(scenario) -> None:
    client_addr, server_addr, w, send = scenario
    reply = send(server_addr, b"a" * 1000)

    cutoff = None
    while True:
        p = w.recv()

        if p.ip.packet_len != len(p.raw):
            assert cutoff is None
            cutoff = p.ip.packet_len - len(p.raw)
            p.ip.packet_len = len(p.raw)  # fix length
            if p.udp:
                p.udp.payload_len = len(p.payload)
        w.send(p)
        done = p.udp and p.dst_port == client_addr[1] or p.tcp and p.tcp.fin
        if done:
            break
    assert cutoff
    assert reply.get(timeout=10) == b"A" * (1000 - cutoff)


def test_check_filter():

    res, pos, msg = WinDivert.check_filter("true")
    assert res
    assert pos == 0
    assert msg is not None
    res, pos, msg = WinDivert.check_filter("something wrong here")
    assert not res
    assert pos == 0
    assert msg is not None
    res, pos, msg = WinDivert.check_filter("outbound and something wrong here")
    assert not res
    assert pos == 13
