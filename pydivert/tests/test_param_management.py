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
from unittest.mock import patch

import pytest

import pydivert
from pydivert.consts import Param

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="WinDivert specific tests")

@pytest.fixture
def mock_windivert_dll():
    with patch("pydivert.windivert.windivert_dll") as mock:
        mock.WinDivertOpen.return_value = 123
        yield mock


def test_get_param_success(mock_windivert_dll):
    w = pydivert.PyDivert()
    getattr(w, "_impl", w)._handle = cast(Any, 123)

    # We simulate WinDivertGetParam returning success and setting the value via byref
    def side_effect(handle, param, pValue):
        if param == Param.QUEUE_LEN:
            pValue._obj.value = 42
        elif param == Param.QUEUE_SIZE:
            pValue._obj.value = 8388608
        return True

    mock_windivert_dll.WinDivertGetParam.side_effect = side_effect

    value = w.get_param(Param.QUEUE_LEN)
    assert value == 42
    assert mock_windivert_dll.WinDivertGetParam.called
    args = mock_windivert_dll.WinDivertGetParam.call_args[0]
    assert args[0] == 123
    assert args[1] == Param.QUEUE_LEN

    # Test getting QUEUE_SIZE
    value = w.get_param(Param.QUEUE_SIZE)
    assert value == 8388608
    args = mock_windivert_dll.WinDivertGetParam.call_args[0]
    assert args[0] == 123
    assert args[1] == Param.QUEUE_SIZE


def test_set_param_success(mock_windivert_dll):
    w = pydivert.PyDivert()
    getattr(w, "_impl", w)._handle = cast(Any, 123)

    mock_windivert_dll.WinDivertSetParam.return_value = True

    result = w.set_param(Param.QUEUE_TIME, 1024)

    assert result is True
    mock_windivert_dll.WinDivertSetParam.assert_called_with(123, Param.QUEUE_TIME, 1024)

    # Test setting QUEUE_SIZE
    result = w.set_param(Param.QUEUE_SIZE, 8388608)
    assert result is True
    mock_windivert_dll.WinDivertSetParam.assert_called_with(123, Param.QUEUE_SIZE, 8388608)

    # Test setting QUEUE_LEN
    result = w.set_param(Param.QUEUE_LEN, 4096)
    assert result is True
    mock_windivert_dll.WinDivertSetParam.assert_called_with(123, Param.QUEUE_LEN, 4096)


def test_get_param_error(mock_windivert_dll):
    w = pydivert.PyDivert()
    getattr(w, "_impl", w)._handle = cast(Any, 123)

    mock_windivert_dll.WinDivertGetParam.side_effect = OSError(None, "Invalid Parameter", None, 87)

    with pytest.raises(OSError):
        w.get_param(cast(Any, 42))  # Invalid parameter


def test_set_param_error(mock_windivert_dll):
    w = pydivert.PyDivert()
    getattr(w, "_impl", w)._handle = cast(Any, 123)

    mock_windivert_dll.WinDivertSetParam.side_effect = OSError(None, "Invalid Parameter", None, 87)

    with pytest.raises(OSError):
        w.set_param(cast(Any, 42), 100)  # Invalid parameter
