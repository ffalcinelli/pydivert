from unittest.mock import MagicMock, patch

import pytest

from pydivert import windivert_dll


def test_raise_on_error_set_last_error_failure():
    # Test line 126-127: SetLastError failure
    mock_func = MagicMock()
    mock_func.__name__ = "MockFunc"
    mock_func.return_value = False

    decorated = windivert_dll.raise_on_error(mock_func)

    with patch("pydivert.windivert_dll.GetLastError", return_value=123):
        with patch("pydivert.windivert_dll.windll") as mock_windll:
            # Trigger exception in SetLastError
            mock_windll.kernel32.SetLastError.side_effect = Exception("Mocked error")

            with pytest.raises(OSError):
                decorated()

            mock_windll.kernel32.SetLastError.assert_called_once_with(0)

def test_raise_on_error_no_error_pending():
    # Just to be sure we cover the basic failure path
    mock_func = MagicMock()
    mock_func.__name__ = "MockFunc"
    mock_func.return_value = False

    decorated = windivert_dll.raise_on_error(mock_func)

    with patch("pydivert.windivert_dll.GetLastError", return_value=0):
        # returns False but GetLastError is 0? (Shouldn't happen with WinDivert but test the wrapper)
        assert not decorated()
