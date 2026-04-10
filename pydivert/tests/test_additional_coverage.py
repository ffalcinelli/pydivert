# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import pytest
from pydivert.filter import transpile
from pydivert.packet import Packet
from unittest.mock import MagicMock, patch

def test_transpile_errors():
    with pytest.raises(Exception):
        transpile("invalid[[]")

def test_packet_edge_cases():
    # Minimal IPv4 + UDP header
    raw = b"\x45\x00\x00\x1c\x00\x01\x00\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01" + \
          b"\x00\x35\x00\x35\x00\x08\x00\x00"
    p = Packet(raw)
    assert p.udp is not None
    
    # Checksum for packet with unknown protocol
    p2 = Packet(b"\x45\x00\x00\x14\x00\x01\x00\x00\x40\xff\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    p2.ip.protocol = 254 # Unknown
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
