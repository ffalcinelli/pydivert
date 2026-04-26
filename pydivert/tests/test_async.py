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
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest

import pydivert
import pydivert.windivert_dll
from pydivert.windivert_dll import Overlapped, WinDivertAddress

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="WinDivert specific tests")


@pytest.fixture
def mock_windivert_dll():
    with patch("pydivert.windivert.windivert_dll") as mock:
        # Mock HANDLE
        mock.WinDivertOpen.return_value = 123
        mock.ERROR_IO_PENDING = 997
        yield mock


def test_recv_ex_async_pending(mock_windivert_dll):
    # Simulate WinDivertRecvEx raising ERROR_IO_PENDING
    mock_windivert_dll.WinDivertRecvEx.side_effect = pydivert.windivert_dll.WinError(997)

    w = pydivert.PyDivert()
    getattr(w, "_impl", w)._handle = cast(Any, 123)
    overlapped = Overlapped()

    result = w.recv_ex(overlapped=overlapped)

    assert result is None
    # Verify references are stored in overlapped to prevent GC
    assert hasattr(overlapped, "_packet_buffer")
    assert hasattr(overlapped, "_address")
    assert hasattr(overlapped, "_recv_len")
    assert mock_windivert_dll.WinDivertRecvEx.called


def test_send_ex_async_pending(mock_windivert_dll):
    # Simulate WinDivertSendEx raising ERROR_IO_PENDING
    mock_windivert_dll.WinDivertSendEx.side_effect = pydivert.windivert_dll.WinError(997)

    w = pydivert.PyDivert()
    getattr(w, "_impl", w)._handle = cast(Any, 123)
    overlapped = Overlapped()

    packet = MagicMock(spec=pydivert.Packet)
    packet.raw = bytearray(b"test")
    packet.wd_addr = WinDivertAddress()

    result = w.send_ex(packet, overlapped=overlapped)

    assert result is None
    # Verify references are stored in overlapped to prevent GC
    assert hasattr(overlapped, "_packet_raw")
    assert hasattr(overlapped, "_address")
    assert hasattr(overlapped, "_send_len")
    assert mock_windivert_dll.WinDivertSendEx.called


def test_recv_ex_sync_success(mock_windivert_dll):
    # Simulate synchronous success (no error raised)
    mock_windivert_dll.WinDivertRecvEx.return_value = True

    w = pydivert.PyDivert()
    getattr(w, "_impl", w)._handle = cast(Any, 123)

    # We need to mock the Packet creation or let it fail gracefully
    with patch("pydivert.windivert.Packet") as mock_packet:
        result = w.recv_ex()
        assert result == mock_packet.return_value
        assert not mock_windivert_dll.WinDivertRecvEx.call_args[0][-1]  # overlapped is None
