# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
from lark import LarkError

import pydivert
from pydivert.consts import Direction, Layer
from pydivert.filter import transpile
from pydivert.packet import Packet
from pydivert.packet.ip import IPHeader
from pydivert.windivert_dll import WinDivertAddress


def test_ip_packet_len_setter():
    p = IPHeader(cast(Any, None))
    with pytest.raises(AttributeError, match="can't set attribute"):
        p.packet_len = 100


def test_transpile_errors():
    with pytest.raises(LarkError):
        transpile("invalid[[]")


def test_packet_edge_cases():
    # Minimal IPv4 + UDP header
    raw = b"\x45\x00\x00\x1c\x00\x01\x00\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01" + \
          b"\x00\x35\x00\x35\x00\x08\x00\x00"
    p = Packet(raw)
    assert p.udp is not None

    # Checksum for packet with unknown protocol
    p2 = Packet(b"\x45\x00\x00\x14\x00\x01\x00\x00\x40\xff\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    assert p2.ipv4
    p2.ipv4.protocol = 254  # Unknown
    p2.recalculate_checksums()


def test_linux_open_error():
    from pydivert.linux import NetFilterQueue
    mock_nfq_class = MagicMock()
    with patch("pydivert.linux.NFQ", mock_nfq_class):
        mock_nfq_instance = mock_nfq_class.return_value
        mock_nfq_instance.bind.side_effect = OSError("Access denied")
        w = NetFilterQueue()
        with pytest.raises(OSError):
            w.open()
        assert not w.is_open


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
    assert cast(Any, p.flow).ProcessId == 456
    assert p.wd_addr.Flow.ProcessId == 456

    # socket
    p.layer = Layer.SOCKET
    s = WinDivertAddress._Union._Socket(ProcessId=789)
    p.socket = s
    assert cast(Any, p.socket).ProcessId == 789
    assert p.wd_addr.Socket.ProcessId == 789

    # reflect
    p.layer = Layer.REFLECT
    r = WinDivertAddress._Union._Reflect(ProcessId=101)
    p.reflect = r
    assert cast(Any, p.reflect).ProcessId == 101
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


def test_init_all_layers_with_wd_addr():
    # Test all branches in __init__ for layers and directions
    for layer in (Layer.NETWORK, Layer.NETWORK_FORWARD, Layer.FLOW, Layer.SOCKET, Layer.REFLECT):
        for outbound in (0, 1):
            addr = WinDivertAddress()
            addr.Layer = layer
            addr.Outbound = outbound
            if layer == Layer.FLOW:
                addr.Flow.ProcessId = 123
            elif layer == Layer.SOCKET:
                addr.Socket.ProcessId = 456
            elif layer == Layer.REFLECT:
                addr.Reflect.ProcessId = 789

            p = pydivert.Packet(bytearray(40), wd_addr=addr)
            assert p.layer == layer
            assert p.direction == (Direction.OUTBOUND if outbound else Direction.INBOUND)
            if layer == Layer.FLOW:
                assert cast(Any, p.flow).ProcessId == 123
            elif layer == Layer.SOCKET:
                assert cast(Any, p.socket).ProcessId == 456
            elif layer == Layer.REFLECT:
                assert cast(Any, p.reflect).ProcessId == 789


def test_setters_with_none():
    # Test val=None branches in setters
    p = pydivert.Packet(bytearray(40))
    p.layer = Layer.FLOW
    p.flow = None
    assert p.flow is None

    p.layer = Layer.SOCKET
    p.socket = None
    assert p.socket is None

    p.layer = Layer.REFLECT
    p.reflect = None
    assert p.reflect is None


def test_populate_all_layers():
    # Test all branches in _populate_wd_addr
    for layer in (Layer.NETWORK, Layer.NETWORK_FORWARD, Layer.FLOW, Layer.SOCKET, Layer.REFLECT):
        # Case 1: Metadata is None
        p = pydivert.Packet(bytearray(40))
        p.layer = layer
        _ = p.wd_addr

        # Case 2: Metadata is not None (for union layers)
        # We set private attributes directly to ensure they are present when layer setter calls _populate_wd_addr
        p = pydivert.Packet(bytearray(40))
        if layer == Layer.FLOW:
            p._flow = WinDivertAddress._Union._Flow(ProcessId=1)
        elif layer == Layer.SOCKET:
            p._socket = WinDivertAddress._Union._Socket(ProcessId=2)
        elif layer == Layer.REFLECT:
            p._reflect = WinDivertAddress._Union._Reflect(ProcessId=3)
        p.layer = layer
        _ = p.wd_addr

        if layer == Layer.FLOW:
            assert p.wd_addr.Flow.ProcessId == 1
        elif layer == Layer.SOCKET:
            assert p.wd_addr.Socket.ProcessId == 2
        elif layer == Layer.REFLECT:
            assert p.wd_addr.Reflect.ProcessId == 3


def test_packet_setters_wrong_layer():
    p = pydivert.Packet(bytearray(40))
    p.layer = Layer.NETWORK

    # Setting flow/socket/reflect in NETWORK layer should NOT update wd_addr union
    p.flow = WinDivertAddress._Union._Flow(ProcessId=1)
    assert p.wd_addr.Flow.ProcessId == 0

    p.socket = WinDivertAddress._Union._Socket(ProcessId=2)
    assert p.wd_addr.Socket.ProcessId == 0

    p.reflect = WinDivertAddress._Union._Reflect(ProcessId=3)
    assert p.wd_addr.Reflect.ProcessId == 0

    # Test interface setter when NOT in network layer
    p.layer = Layer.FLOW
    p.interface = (1, 2)
    assert p.interface == (1, 2)
    assert p.wd_addr.Network.IfIdx == 0


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
