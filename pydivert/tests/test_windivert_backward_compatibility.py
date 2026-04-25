# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys
from unittest.mock import patch

import pytest

import pydivert


def test_windivert_backward_compatibility_import():
    """Ensure pydivert.WinDivert is still accessible as it was in version >= 3.1.0."""
    from pydivert.windivert import WinDivert
    assert WinDivert is pydivert.WinDivert

def test_windivert_basic_usage():
    """Ensure WinDivert can be instantiated and used as a context manager (mocked)."""
    if sys.platform != "win32":
        pytest.skip("WinDivert implementation only exists on Windows (or mocked)")

    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        mock_dll.WinDivertOpen.return_value = 123
        mock_dll.WinDivertClose.return_value = True

        from pydivert.windivert import WinDivert
        with WinDivert("false") as w:
            assert w.is_open
            assert w.handle == 123

        assert mock_dll.WinDivertOpen.called
        assert mock_dll.WinDivertClose.called

def test_windivert_static_methods():
    """Ensure static methods like check_filter are still available on WinDivert."""
    if sys.platform != "win32":
         pytest.skip("WinDivert implementation only exists on Windows (or mocked)")

    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        from pydivert.windivert import WinDivert

        # Mocking check_filter behavior (it calls WinDivertHelperCompileFilter)
        mock_dll.WinDivertHelperCompileFilter.return_value = True

        res, pos, msg = WinDivert.check_filter("true")
        assert res is True
        assert mock_dll.WinDivertHelperCompileFilter.called
