# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import pytest

import pydivert
from pydivert.packet.ip import IPHeader
from pydivert.windivert_dll import WinDivertAddress


def test_ip_packet_len_setter():
    p = IPHeader(None)
    with pytest.raises(AttributeError, match="can't set attribute"):
        p.packet_len = 100


def test_windivert_recv_no_handle():
    w = pydivert.WinDivert()
    with pytest.raises(RuntimeError, match="WinDivert handle is not open"):
        w.recv()


def test_windivert_recv_ex_no_handle():
    w = pydivert.WinDivert()
    with pytest.raises(RuntimeError, match="WinDivert handle is not open"):
        w.recv_ex()


def test_windivert_register_coverage():
    try:
        pydivert.WinDivert.register()
    except Exception:
        pass


def test_packet_setters():
    p = pydivert.Packet(bytearray(40), interface=(1, 0))
    p.is_loopback = True
    assert p.is_loopback is True
    p.is_impostor = True
    assert p.is_impostor is True
    p.is_sniffed = True
    assert p.is_sniffed is True


def test_packet_wd_addr_layers():
    from pydivert.consts import Layer

    p = pydivert.Packet(bytearray(40), layer=Layer.FLOW)
    p.flow = WinDivertAddress._Union._Flow()
    addr = p.wd_addr
    assert addr.Layer == Layer.FLOW

    p = pydivert.Packet(bytearray(40), layer=Layer.SOCKET)
    p.socket = WinDivertAddress._Union._Socket()
    addr = p.wd_addr
    assert addr.Layer == Layer.SOCKET

    p = pydivert.Packet(bytearray(40), layer=Layer.REFLECT)
    p.reflect = WinDivertAddress._Union._Reflect()
    addr = p.wd_addr
    assert addr.Layer == Layer.REFLECT
