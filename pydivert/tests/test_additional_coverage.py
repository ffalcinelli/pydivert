# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from typing import Any, cast
import pytest
import pydivert
from pydivert.packet.ip import IPHeader
from pydivert.windivert_dll import WinDivertAddress
from pydivert.consts import Layer, Direction

def test_ip_packet_len_setter():
    p = IPHeader(cast(Any, None))
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

def test_packet_all_metadata_properties():
    p = pydivert.Packet(bytearray(40))

    # interface
    p.interface = (1, 2)
    assert p.interface == (1, 2)
    assert p.wd_addr.Network.IfIdx == 1
    assert p.wd_addr.Network.SubIfIdx == 2

    # direction
    p.direction = Direction.INBOUND
    assert p.direction == Direction.INBOUND
    assert p.wd_addr.Outbound == 0
    assert p.is_inbound
    assert not p.is_outbound

    p.direction = Direction.OUTBOUND
    assert p.direction == Direction.OUTBOUND
    assert p.wd_addr.Outbound == 1
    assert p.is_outbound
    assert not p.is_inbound

    # timestamp
    p.timestamp = 123456789
    assert p.timestamp == 123456789
    assert p.wd_addr.Timestamp == 123456789

    # loopback
    p.is_loopback = True
    assert p.is_loopback is True
    assert p.wd_addr.Loopback == 1
    p.is_loopback = False
    assert p.is_loopback is False
    assert p.wd_addr.Loopback == 0

    # impostor
    p.is_impostor = True
    assert p.is_impostor is True
    assert p.wd_addr.Impostor == 1
    p.is_impostor = False
    assert p.is_impostor is False
    assert p.wd_addr.Impostor == 0

    # sniffed
    p.is_sniffed = True
    assert p.is_sniffed is True
    assert p.wd_addr.Sniffed == 1
    p.is_sniffed = False
    assert p.is_sniffed is False
    assert p.wd_addr.Sniffed == 0

    # ip_checksum
    p.ip_checksum = True
    assert p.ip_checksum is True
    assert p.wd_addr.IPChecksum == 1
    p.ip_checksum = False
    assert p.ip_checksum is False
    assert p.wd_addr.IPChecksum == 0

    # tcp_checksum
    p.tcp_checksum = True
    assert p.tcp_checksum is True
    assert p.wd_addr.TCPChecksum == 1
    p.tcp_checksum = False
    assert p.tcp_checksum is False
    assert p.wd_addr.TCPChecksum == 0

    # udp_checksum
    p.udp_checksum = True
    assert p.udp_checksum is True
    assert p.wd_addr.UDPChecksum == 1
    p.udp_checksum = False
    assert p.udp_checksum is False
    assert p.wd_addr.UDPChecksum == 0

    # event
    p.event = 2
    assert p.event == 2
    assert p.wd_addr.Event == 2

    # layer
    p.layer = Layer.NETWORK_FORWARD
    assert p.layer == Layer.NETWORK_FORWARD
    assert p.wd_addr.Layer == Layer.NETWORK_FORWARD

    # flow
    p.layer = Layer.FLOW
    f = WinDivertAddress._Union._Flow(ProcessId=456)
    p.flow = f
    assert p.flow.ProcessId == 456
    assert p.wd_addr.Flow.ProcessId == 456

    # socket
    p.layer = Layer.SOCKET
    s = WinDivertAddress._Union._Socket(ProcessId=789)
    p.socket = s
    assert p.socket.ProcessId == 789
    assert p.wd_addr.Socket.ProcessId == 789

    # reflect
    p.layer = Layer.REFLECT
    r = WinDivertAddress._Union._Reflect(ProcessId=101)
    p.reflect = r
    assert p.reflect.ProcessId == 101
    assert p.wd_addr.Reflect.ProcessId == 101

    # Test __repr__
    assert "Packet" in repr(p)

def test_packet_wd_addr_persistence():
    p = pydivert.Packet(bytearray(40))
    p.wd_addr.IPChecksum = 1
    # Without dirtying the packet, the cached wd_addr should retain the manual change
    assert p.wd_addr.IPChecksum == 1

    # If we dirty it, it should be overwritten
    p.ip_checksum = False
    assert p.wd_addr.IPChecksum == 0

def test_union_clearing():
    p = pydivert.Packet(bytearray(40))
    p.layer = Layer.FLOW
    p.flow = WinDivertAddress._Union._Flow(ProcessId=1234)
    assert p.wd_addr.Flow.ProcessId == 1234

    p.layer = Layer.NETWORK
    # This should clear the union
    assert p.wd_addr.Flow.ProcessId == 0

def test_packet_checksum_logic():
    # IPv4 UDP packet
    raw = bytes.fromhex("4500001c00000000401100000101010102020202") + bytes(8)
    p = pydivert.Packet(raw)

    # Test recalculate_checksums (driver may not be present, so catch error)
    try:
        p.recalculate_checksums()
    except (OSError, FileNotFoundError):
        pass

    # Test is_checksum_valid
    try:
        _ = p.is_checksum_valid
    except (OSError, FileNotFoundError):
        pass

def test_packet_init_with_wd_addr():
    addr = WinDivertAddress()
    addr.Timestamp = 12345
    addr.Layer = Layer.FLOW
    addr.Event = 1
    addr.Outbound = 1
    addr.Flow.ProcessId = 678

    p = pydivert.Packet(bytearray(40), wd_addr=addr)
    assert p.timestamp == 12345
    assert p.layer == Layer.FLOW
    assert p.event == 1
    assert p.direction == Direction.OUTBOUND
    assert p.flow.ProcessId == 678
    assert p.wd_addr is addr

    # Test with other layers in init
    addr2 = WinDivertAddress()
    addr2.Layer = Layer.SOCKET
    addr2.Socket.ProcessId = 999
    p2 = pydivert.Packet(bytearray(40), wd_addr=addr2)
    assert p2.layer == Layer.SOCKET
    assert p2.socket.ProcessId == 999

    addr3 = WinDivertAddress()
    addr3.Layer = Layer.REFLECT
    addr3.Reflect.ProcessId = 888
    p3 = pydivert.Packet(bytearray(40), wd_addr=addr3)
    assert p3.layer == Layer.REFLECT
    assert p3.reflect.ProcessId == 888
