import subprocess
from unittest.mock import patch

from pydivert.windivert import WinDivert


def test_is_registered_calls_subprocess_with_list():
    with patch("subprocess.call") as mock_call:
        mock_call.return_value = 0
        WinDivert.is_registered()
        mock_call.assert_called_once_with(["sc", "query", "WinDivert"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def test_unregister_calls_subprocess_with_list():
    with patch("subprocess.check_call") as mock_check_call:
        WinDivert.unregister()
        mock_check_call.assert_called_once_with(
            ["sc", "stop", "WinDivert"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
