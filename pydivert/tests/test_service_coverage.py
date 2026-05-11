from unittest.mock import MagicMock, patch

from pydivert import service


def test_is_registered_no_advapi32():
    with patch("pydivert.service._get_advapi32", return_value=None):
        assert service.is_registered() is False


def test_is_registered_scm_failure():
    mock_advapi = MagicMock()
    mock_advapi.OpenSCManagerW.return_value = 0
    with patch("pydivert.service._get_advapi32", return_value=mock_advapi):
        assert service.is_registered() is False
        mock_advapi.OpenSCManagerW.assert_called_once()


def test_is_registered_success():
    mock_advapi = MagicMock()
    mock_advapi.OpenSCManagerW.return_value = 123
    mock_advapi.OpenServiceW.return_value = 456
    with patch("pydivert.service._get_advapi32", return_value=mock_advapi):
        from unittest.mock import call

        assert service.is_registered() is True
        mock_advapi.CloseServiceHandle.assert_has_calls([call(456), call(123)], any_order=True)
        assert mock_advapi.CloseServiceHandle.call_count == 2


def test_is_registered_not_found():
    mock_advapi = MagicMock()
    mock_advapi.OpenSCManagerW.return_value = 123
    mock_advapi.OpenServiceW.return_value = 0
    with patch("pydivert.service._get_advapi32", return_value=mock_advapi):
        assert service.is_registered() is False
        mock_advapi.CloseServiceHandle.assert_called_once_with(123)


def test_stop_service_no_advapi32():
    with patch("pydivert.service._get_advapi32", return_value=None):
        assert service.stop_service() is False


def test_stop_service_scm_failure():
    mock_advapi = MagicMock()
    mock_advapi.OpenSCManagerW.return_value = 0
    with patch("pydivert.service._get_advapi32", return_value=mock_advapi):
        assert service.stop_service() is False


def test_stop_service_open_service_failure():
    mock_advapi = MagicMock()
    mock_advapi.OpenSCManagerW.return_value = 123
    mock_advapi.OpenServiceW.return_value = 0
    with patch("pydivert.service._get_advapi32", return_value=mock_advapi):
        assert service.stop_service() is False
        mock_advapi.CloseServiceHandle.assert_called_once_with(123)


def test_stop_service_control_service_failure():
    mock_advapi = MagicMock()
    mock_advapi.OpenSCManagerW.return_value = 123
    mock_advapi.OpenServiceW.return_value = 456
    mock_advapi.ControlService.return_value = 0
    with patch("pydivert.service._get_advapi32", return_value=mock_advapi):
        assert service.stop_service() is False
        # scm + service handle
        assert mock_advapi.CloseServiceHandle.call_count == 2


def test_stop_service_success():
    mock_advapi = MagicMock()
    mock_advapi.OpenSCManagerW.return_value = 123
    mock_advapi.OpenServiceW.return_value = 456
    mock_advapi.ControlService.return_value = 1
    with patch("pydivert.service._get_advapi32", return_value=mock_advapi):
        assert service.stop_service() is True
        assert mock_advapi.CloseServiceHandle.call_count == 2
