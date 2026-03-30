import ctypes
from unittest.mock import patch

import pytest

from pydivert import WinDivert


def test_get_last_error_leak_mock():
    # ERROR_INVALID_PARAMETER (87)
    error_code = 87

    # We patch the GetLastError that the decorator uses.
    # Even if it returns 87, w.open() should NOT raise because it succeeds.
    with patch("pydivert.windivert_dll.GetLastError", return_value=error_code):
        w = WinDivert("false")
        try:
            # This should NO LONGER raise OSError after the fix
            w.open()
        except OSError as e:
            pytest.fail(
                f"Bug still present: WinDivert.open() raised [Error {e.winerror}] "
                f"even though GetLastError was mocked to 87 but call succeeded"
            )
        finally:
            if w.is_open:
                w.close()


def test_get_last_error_leak_real():
    # Test with real SetLastError
    error_code = 1234
    try:
        ctypes.windll.kernel32.SetLastError(error_code)
    except (AttributeError, OSError):
        pytest.skip("SetLastError not available (non-Windows)")

    w = WinDivert("false")
    try:
        # Should not raise
        w.open()
    except OSError as e:
        if e.winerror == error_code:
            pytest.fail(f"Bug still present: WinDivert.open() raised [Error {e.winerror}] with real SetLastError(1234)")
        else:
            raise
    finally:
        if w.is_open:
            w.close()


def test_get_param_leak_mock():
    # ERROR_SERVICE_DOES_NOT_EXIST (1234)
    error_code = 1234

    w = WinDivert("false")
    w.open()

    try:
        from pydivert.consts import Param

        with patch("pydivert.windivert_dll.GetLastError", return_value=error_code):
            try:
                # Should not raise
                w.get_param(Param.QUEUE_LEN)
            except OSError as e:
                pytest.fail(
                    f"Bug still present: WinDivert.get_param() raised [Error {e.winerror}] even though call succeeded"
                )
    finally:
        w.close()
