# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
from unittest.mock import patch

from pydivert.windivert import WinDivert


def test_is_registered_calls_subprocess_with_list():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        WinDivert.is_registered()
        mock_run.assert_called_once_with(["sc", "query", "WinDivert"], capture_output=True)


def test_unregister_calls_subprocess_with_list():
    with patch("subprocess.run") as mock_run:
        WinDivert.unregister()
        mock_run.assert_called_once_with(["sc", "stop", "WinDivert"], capture_output=True, check=True)
