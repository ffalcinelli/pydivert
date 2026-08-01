from unittest.mock import patch

from pydivert.tests.test_real_world import test_use_case_monitor


def test_use_case_monitor_exception():
    with patch("socket.socket.connect", side_effect=OSError("mocked connection failure")):
        test_use_case_monitor()
