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

def test_windivert_dll_getattr():
    # Test line 271-272: __getattr__ success
    # Access a function that exists in WINDIVERT_FUNCTIONS but we use getattr() or just direct access
    # before it's been initialized (though it's already initialized by the loop at the end of the module).
    # To truly test __getattr__, we can delete one from the module first.
    if hasattr(windivert_dll, "WinDivertOpen"):
        # We don't want to actually delete it from the real module permanently, 
        # but for the test we can.
        func = windivert_dll.WinDivertOpen
        delattr(windivert_dll, "WinDivertOpen")
        try:
            # This should trigger __getattr__
            assert windivert_dll.WinDivertOpen is not None
        finally:
            setattr(windivert_dll, "WinDivertOpen", func)

    # Test __getattr__ failure (line 273)
    with pytest.raises(AttributeError):
        windivert_dll.NonExistentFunction
