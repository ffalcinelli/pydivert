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

import pytest

from pydivert.consts import Param
from pydivert.windivert import WinDivert

from .fixtures import scenario
from .fixtures import windivert_handle as w

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
        Tests setting the minimum value for queue time.
        From docs: 128 < default 512 < 2048
        """
        def_range = (128, 512, 2048)
        for value in def_range:
            w.set_param(Param.QUEUE_TIME, value)
            assert value == w.get_param(Param.QUEUE_TIME)

    @pytest.mark.skip(reason="Fails on Vagrant VM with WinError 87")
    def test_queue_len_range(self, w):
        """
        Tests setting the minimum value for queue length.
        From docs: 2 <= queue length <= 16384
        """
        for value in (2, 512, 16384):
            w.set_param(Param.QUEUE_LEN, value)
            assert value == w.get_param(Param.QUEUE_LEN)

    @pytest.mark.skip(reason="Fails on Vagrant VM with WinError 87")
    def test_queue_size_range(self, w):
        """
        Tests setting the minimum value for queue size.
        From docs: 4096 <= queue size <= 33554432
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

    def test_get_param_mocked(self):
        from unittest.mock import patch

        with patch("pydivert.windivert.windivert_dll") as mock_dll:
            w = WinDivert("false")
            w._handle = 12345

            def side_effect(handle, param, pValue):
                if param == Param.QUEUE_LEN:
                    pValue._obj.value = 42
                elif param == Param.QUEUE_SIZE:
                    pValue._obj.value = 8388608
                return True

            mock_dll.WinDivertGetParam.side_effect = side_effect

            value = w.get_param(Param.QUEUE_LEN)
            assert value == 42
            assert mock_dll.WinDivertGetParam.called
            args = mock_dll.WinDivertGetParam.call_args[0]
            assert args[0] == 12345
            assert args[1] == Param.QUEUE_LEN

            value = w.get_param(Param.QUEUE_SIZE)
            assert value == 8388608
            args = mock_dll.WinDivertGetParam.call_args[0]
            assert args[0] == 12345
            assert args[1] == Param.QUEUE_SIZE


def test_echo(scenario):
    client_addr, server_addr, w, send = scenario
    w = w  # type: WinDivert
    reply = send(server_addr, b"echo")

    for p in w:
        assert p.is_loopback
        assert p.is_outbound
        w.send(p)
        done = p.udp and p.dst_port == client_addr[1] or p.tcp and p.tcp.fin
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

        done = p.udp and p.dst_port == client_addr[1] or p.tcp and p.tcp.fin
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

        done = p.udp and p.dst_port == client_addr[1] or p.tcp and p.tcp.fin
        if done:
            break
    assert reply.get() == b"ECHO"


@pytest.mark.skip(reason="Fails on Vagrant VM: packets are not truncated as expected")
def test_packet_cutoff(scenario):
    client_addr, server_addr, w, send = scenario
    w = w  # type: WinDivert
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
    assert reply.get() == b"A" * (1000 - cutoff)


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
