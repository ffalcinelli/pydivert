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
# see <http://www.gnu.org/licenses/>.

from unittest.mock import patch

import pytest

import pydivert
from pydivert.consts import Param


@pytest.fixture
def mock_windivert_dll():
    with patch("pydivert.windivert.windivert_dll") as mock:
        mock.WinDivertOpen.return_value = 123
        yield mock


def test_get_param_success(mock_windivert_dll):
    w = pydivert.WinDivert()
    w._handle = 123

    # We simulate WinDivertGetParam returning success and setting the value via byref
    def side_effect(handle, param, pValue):
        pValue._obj.value = 42
        return True

    mock_windivert_dll.WinDivertGetParam.side_effect = side_effect

    value = w.get_param(Param.QUEUE_LEN)

    assert value == 42
    assert mock_windivert_dll.WinDivertGetParam.called

    # Check that it was called with the right arguments
    args = mock_windivert_dll.WinDivertGetParam.call_args[0]
    assert args[0] == 123
    assert args[1] == Param.QUEUE_LEN
    # The third argument is a byref object, we can't easily assert equality on it directly


def test_set_param_success(mock_windivert_dll):
    w = pydivert.WinDivert()
    w._handle = 123

    mock_windivert_dll.WinDivertSetParam.return_value = True

    result = w.set_param(Param.QUEUE_TIME, 1024)

    assert result is True
    mock_windivert_dll.WinDivertSetParam.assert_called_once_with(123, Param.QUEUE_TIME, 1024)


def test_get_param_error(mock_windivert_dll):
    w = pydivert.WinDivert()
    w._handle = 123

    mock_windivert_dll.WinDivertGetParam.side_effect = OSError(None, "Invalid Parameter", None, 87)

    with pytest.raises(OSError):
        w.get_param(42)  # Invalid parameter


def test_set_param_error(mock_windivert_dll):
    w = pydivert.WinDivert()
    w._handle = 123

    mock_windivert_dll.WinDivertSetParam.side_effect = OSError(None, "Invalid Parameter", None, 87)

    with pytest.raises(OSError):
        w.set_param(42, 100)  # Invalid parameter
