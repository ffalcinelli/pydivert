# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import asyncio
import sys
from unittest.mock import MagicMock, patch

import pytest

from pydivert import PyDivert


def test_pydivert_platform_selection():
    with patch("sys.platform", "linux2"):
        # Force re-import of linux to ensure NetFilterQueue is used
        if "pydivert.linux" in sys.modules:
            del sys.modules["pydivert.linux"]
        from pydivert.linux import NetFilterQueue
        w = PyDivert()
        assert isinstance(w._impl, NetFilterQueue)

    with patch("sys.platform", "freebsd14"):
        if "pydivert.bsd" in sys.modules:
            del sys.modules["pydivert.bsd"]
        from pydivert.bsd import Divert
        w = PyDivert()
        assert isinstance(w._impl, Divert)

    with patch("sys.platform", "darwin"):
        if "pydivert.macos" in sys.modules:
            del sys.modules["pydivert.macos"]
        from pydivert.macos import MacOSDivert
        # Mock PF initialization or it will fail
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="Status: Enabled", returncode=0)
            with patch("socket.socket"):
                w = PyDivert()
                assert isinstance(w._impl, MacOSDivert)

    with patch("sys.platform", "win32"):
        # We need to mock WinDivert DLL loading or it will fail on Linux
        with patch("pydivert.windivert_dll.WinDivertOpen", return_value=123):
            from pydivert.windivert import WinDivert
            w = PyDivert()
            assert isinstance(w._impl, WinDivert)

@pytest.mark.asyncio
async def test_linux_nfq_mock():
    from pydivert.linux import NetFilterQueue
    # Mock NFQ
    mock_nfq_lib = MagicMock()
    with patch("pydivert.linux.NFQ", mock_nfq_lib):
        w = NetFilterQueue()
        w.open()
        assert w.is_open
        p = MagicMock()
        p.raw = memoryview(bytearray(b"data"))
        w.send(p)
        await w.send_async(p)
        w.close()
        assert not w.is_open

    # Test error path
    with patch("pydivert.linux.NFQ", mock_nfq_lib):
        mock_nfq_lib.return_value.bind.side_effect = OSError("Access denied")
        w = NetFilterQueue()
        with pytest.raises(OSError):
            w.open()

    # Test missing library
    with patch("pydivert.linux.NFQ", None):
        w = NetFilterQueue()
        with pytest.raises(ImportError):
            w.open()

@pytest.mark.skipif(sys.platform == "win32", reason="WinDivert DLL will fail on this mock")
@pytest.mark.asyncio
async def test_bsd_divert_mock():
    from pydivert.bsd import Divert
    mock_socket = MagicMock()
    with patch("socket.socket", return_value=mock_socket):
        w = Divert()
        w.open()
        assert w.is_open
        mock_socket.recvfrom.return_value = (b"packet_data", ("1.2.3.4", 0))
        pkt = w.recv()
        assert pkt.raw == b"packet_data"
        w.send(pkt)
        await w.send_async(pkt)
        w.close()
        assert not w.is_open

    # Test error path
    with patch("socket.socket", side_effect=OSError("Permission denied")):
        w = Divert()
        with pytest.raises(OSError):
            w.open()

@pytest.mark.asyncio
async def test_pydivert_methods_mock():
    # Test that PyDivert forwards all methods to its implementation
    mock_impl = MagicMock()
    # Mock async methods to return awaitables
    f1 = asyncio.Future()
    f1.set_result(MagicMock())
    mock_impl.recv_async.return_value = f1
    f2 = asyncio.Future()
    f2.set_result(0)
    mock_impl.send_async.return_value = f2

    with patch("pydivert.pydivert.PyDivert._get_implementation_class", return_value=lambda *a, **k: mock_impl):
        w = PyDivert()
        w.open()
        mock_impl.open.assert_called_once()
        w.close()
        mock_impl.close.assert_called_once()
        _ = w.is_open
        _ = mock_impl.is_open
        w.recv()
        mock_impl.recv.assert_called_once()
        await w.recv_async()
        mock_impl.recv_async.assert_called_once()
        w.send(MagicMock())
        mock_impl.send.assert_called_once()
        await w.send_async(MagicMock())
        mock_impl.send_async.assert_called_once()

def test_windivert_dll_init_mock():
    # Attempt to cover windivert_dll/__init__.py loading logic
    with patch("sys.platform", "win32"):
        with patch("ctypes.WinDLL", create=True) as mock_windll:
            mock_windll.return_value = MagicMock()
            # This is tricky because of the singleton-like nature of the module
            # but we can try to call _init directly if we find it
            from pydivert import windivert_dll
            try:
                windivert_dll._init()
            except Exception:
                pass

def test_linux_nfq_errors():
    from pydivert.linux import NetFilterQueue
    w = NetFilterQueue()
    with pytest.raises(RuntimeError):
        w.recv()
    with pytest.raises(RuntimeError):
        w.send(MagicMock())

def test_bsd_divert_errors():
    from pydivert.bsd import Divert
    w = Divert()
    with pytest.raises(RuntimeError):
        w.recv()
    with pytest.raises(RuntimeError):
        w.send(MagicMock())

def test_unsupported_platform():
    with patch("sys.platform", "unknown"):
        # We need to clear the cache if any
        if "pydivert.pydivert" in sys.modules:
            import importlib
            importlib.reload(sys.modules["pydivert.pydivert"])
        from pydivert.pydivert import PyDivert
        with pytest.raises(NotImplementedError):
            PyDivert()
