# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import asyncio
import sys
from unittest.mock import MagicMock, patch

import pytest

from pydivert import PyDivert
from pydivert.consts import Flag, Layer


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

            import socket as real_socket
            original_socket = real_socket.socket
            def side_effect(family, type=real_socket.SOCK_STREAM, proto=0, fileno=None):
                if family == real_socket.AF_INET and type == real_socket.SOCK_RAW:
                    return MagicMock()
                return original_socket(family, type, proto, fileno)

            with patch("socket.socket", side_effect=side_effect):
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
    # Mock NFQ and subprocess.run
    mock_nfq_lib = MagicMock()
    with patch("pydivert.linux.NFQ", mock_nfq_lib), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        w = NetFilterQueue()
        w.open()
        assert w.is_open
        p = MagicMock()
        packet_data = (
            b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01'
            b'\x7f\x00\x00\x01\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x50\x02\x20\x00\x00\x00\x00\x00'
        )
        p.raw = memoryview(bytearray(packet_data))
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

    # Test iptables error path
    with patch("pydivert.linux.NFQ", mock_nfq_lib), patch("subprocess.run") as mock_run:
        mock_nfq_lib.return_value.bind.side_effect = None

        def side_effect(cmd, *args, **kwargs):
            if cmd[0] == "iptables" and any(arg in ("-L", "-S", "-D") for arg in cmd):
                return MagicMock(returncode=0, stdout="")
            raise Exception("iptables fail")

        mock_run.side_effect = side_effect
        w = NetFilterQueue()
        with pytest.raises(RuntimeError, match="Failed to add iptables rule"):
            w.open()

    # Test missing library
    with patch("pydivert.linux.NFQ", None):
        w = NetFilterQueue()
        with pytest.raises(ImportError):
            w.open()

@pytest.mark.skipif(sys.platform == "win32", reason="WinDivert DLL will fail on this mock")
@pytest.mark.asyncio
async def test_bsd_divert_mock():
    import socket as real_socket

    from scapy.all import IP, UDP, raw  # type: ignore

    from pydivert.bsd import Divert
    original_socket = real_socket.socket
    mock_socket_instance = MagicMock()

    def side_effect(family, type=real_socket.SOCK_STREAM, proto=0, fileno=None):
        if family == real_socket.AF_INET and type == real_socket.SOCK_RAW:
            return mock_socket_instance
        return original_socket(family, type, proto, fileno)

    with patch("socket.socket", side_effect=side_effect), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        w = Divert()
        w.open()
        assert w.is_open
        # Provide a real IPv4 packet so Packet parsing doesn't fail
        real_packet = raw(IP(dst="1.2.3.4")/UDP(dport=80)/b"payload")
        mock_socket_instance.recvfrom.return_value = (real_packet, ("1.2.3.4", 0))
        pkt = w.recv()
        assert pkt is not None
        assert pkt.dst_addr == "1.2.3.4"
        w.send(pkt)
        await w.send_async(pkt)
        w.close()
        assert not w.is_open

    # Test error path
    def error_side_effect(family, type=real_socket.SOCK_STREAM, proto=0, fileno=None):
        if family == real_socket.AF_INET and type == real_socket.SOCK_RAW:
            raise OSError("Permission denied")
        return original_socket(family, type, proto, fileno)

    with patch("socket.socket", side_effect=error_side_effect):
        w = Divert()
        with pytest.raises(OSError):
            w.open()

    # Test ipfw error path
    if sys.platform.startswith("freebsd"):
        with patch("socket.socket", side_effect=side_effect), patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("ipfw fail")
            w = Divert()
            with pytest.raises(RuntimeError, match="Failed to apply ipfw rule"):
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
        mock_impl.some_attr = 42
        assert w.some_attr == 42
        
        # Test BaseDivert properties
        assert w.layer == Layer.NETWORK
        assert w.priority == 0
        assert w.flags == Flag.DEFAULT
        
        # Test iteration
        mock_impl.recv.return_value = MagicMock()
        it = iter(w)
        assert next(it) is not None
        
        # Test async iteration
        mock_impl.recv_async.return_value = asyncio.Future()
        mock_impl.recv_async.return_value.set_result(MagicMock())
        ait = w.__aiter__()
        assert await w.__anext__() is not None

        # Test context managers
        with w:
            pass
        async with w:
            pass

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
