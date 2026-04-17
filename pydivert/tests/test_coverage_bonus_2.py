import asyncio
from unittest.mock import MagicMock, patch

import pytest

import pydivert
from pydivert.packet import Packet


def test_windivert_unregister_fallback():
    with patch("pydivert.service.stop_service", return_value=False):
        with patch("subprocess.run") as mock_run:
            pydivert.WinDivert.unregister()
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            # On Linux/Mock, the fallback C:\Windows\System32 should be used
            import os
            expected_sc_path = os.path.join("C:\\Windows\\System32", "sc.exe")
            assert os.path.normcase(args[0]) == os.path.normcase(expected_sc_path)
            assert args[1:] == ["stop", "WinDivert"]


def test_windivert_unregister_success_path():
    from unittest.mock import MagicMock

    with patch("pydivert.service.stop_service", return_value=False):
        with patch("subprocess.run") as mock_run:
            mock_windll = MagicMock()
            mock_windll.kernel32.GetSystemDirectoryW.return_value = 10

            # We need to mock the buffer value since GetSystemDirectoryW would normally fill it
            with patch("ctypes.create_unicode_buffer") as mock_buf:
                buf_instance = MagicMock()
                buf_instance.value = "C:\\MockedSystem32"
                mock_buf.return_value = buf_instance

                with patch("ctypes.windll", mock_windll, create=True):
                    pydivert.WinDivert.unregister()

            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            import os
            expected_sc_path = os.path.join("C:\\MockedSystem32", "sc.exe")
            assert os.path.normcase(args[0]) == os.path.normcase(expected_sc_path)


def test_windivert_unregister_api_zero_path():
    from unittest.mock import MagicMock

    with patch("pydivert.service.stop_service", return_value=False):
        with patch("subprocess.run") as mock_run:
            mock_windll = MagicMock()
            # GetSystemDirectoryW returns 0 on failure
            mock_windll.kernel32.GetSystemDirectoryW.return_value = 0

            with patch("ctypes.windll", mock_windll, create=True):
                pydivert.WinDivert.unregister()

            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            import os
            expected_sc_path = os.path.join("C:\\Windows\\System32", "sc.exe")
            assert os.path.normcase(args[0]) == os.path.normcase(expected_sc_path)


def test_windivert_unregister_api_overflow_path():
    import ctypes.wintypes
    from unittest.mock import MagicMock

    with patch("pydivert.service.stop_service", return_value=False):
        with patch("subprocess.run") as mock_run:
            mock_windll = MagicMock()
            # GetSystemDirectoryW returns length > MAX_PATH if buffer is too small
            mock_windll.kernel32.GetSystemDirectoryW.return_value = ctypes.wintypes.MAX_PATH + 1

            with patch("ctypes.windll", mock_windll, create=True):
                pydivert.WinDivert.unregister()

            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            import os
            expected_sc_path = os.path.join("C:\\Windows\\System32", "sc.exe")
            assert os.path.normcase(args[0]) == os.path.normcase(expected_sc_path)


def test_windivert_unregister_attribute_error():
    with patch("pydivert.service.stop_service", return_value=False):
        with patch("subprocess.run") as mock_run:
            # Simulate AttributeError when accessing ctypes.windll.kernel32 (e.g. on Linux)
            mock_windll = MagicMock(spec=[]) # No attributes allowed

            with patch("ctypes.windll", mock_windll, create=True):
                pydivert.WinDivert.unregister()

            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            import os
            expected_sc_path = os.path.join("C:\\Windows\\System32", "sc.exe")
            assert os.path.normcase(args[0]) == os.path.normcase(expected_sc_path)



def test_check_filter_os_error():
    with patch("pydivert.windivert_dll.WinDivertHelperCompileFilter", side_effect=OSError("Mocked OS Error")):
        res, pos, msg = pydivert.WinDivert.check_filter("true")
        assert res is False
        assert msg == ""


@pytest.mark.asyncio
async def test_async_closed_handle_error():
    w = pydivert.WinDivert()
    # Handle is None
    with pytest.raises(RuntimeError, match="WinDivert handle is not open"):
        await w.recv_async()
    with pytest.raises(RuntimeError, match="WinDivert handle is not open"):
        await w.send_async(Packet(bytearray(20)))


@pytest.mark.asyncio
async def test_recv_async_error_path():
    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        mock_dll.WinDivertOpen.return_value = 123
        mock_dll.CreateEventW.return_value = 456
        mock_dll.WinDivertRecvEx.return_value = False
        mock_dll.GetLastError.return_value = 1234  # Not ERROR_IO_PENDING
        mock_dll.WinError.side_effect = lambda code: OSError(None, "Mocked WinError", None, code)

        async with pydivert.WinDivert() as w:
            with pytest.raises(OSError):
                await w.recv_async()
            assert len(w._pending_ops) == 0


@pytest.mark.asyncio
async def test_send_async_error_path():
    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        mock_dll.WinDivertOpen.return_value = 123
        mock_dll.CreateEventW.return_value = 456
        mock_dll.WinDivertSendEx.return_value = False
        mock_dll.GetLastError.return_value = 1234  # Not ERROR_IO_PENDING
        mock_dll.WinError.side_effect = lambda code: OSError(None, "Mocked WinError", None, code)

        async with pydivert.WinDivert() as w:
            raw = bytearray(b"\x45" + b"\x00" * 39)
            p = Packet(raw)
            assert p.ipv4 is not None
            p.ipv4.packet_len = 40
            with pytest.raises(OSError):
                await w.send_async(p)
            assert len(w._pending_ops) == 0


@pytest.mark.asyncio
async def test_recv_async_exception_path():
    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        mock_dll.WinDivertOpen.return_value = 123
        mock_dll.CreateEventW.return_value = 456
        # Raise unexpected exception during call
        mock_dll.WinDivertRecvEx.side_effect = RuntimeError("Unexpected")

        async with pydivert.WinDivert() as w:
            with pytest.raises(RuntimeError, match="Unexpected"):
                await w.recv_async()
            assert len(w._pending_ops) == 0


@pytest.mark.asyncio
async def test_send_async_exception_path():
    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        mock_dll.WinDivertOpen.return_value = 123
        mock_dll.CreateEventW.return_value = 456
        # Raise unexpected exception during call
        mock_dll.WinDivertSendEx.side_effect = RuntimeError("Unexpected")

        async with pydivert.WinDivert() as w:
            raw = bytearray(b"\x45" + b"\x00" * 39)
            p = Packet(raw)
            assert p.ipv4 is not None
            p.ipv4.packet_len = 40
            with pytest.raises(RuntimeError, match="Unexpected"):
                await w.send_async(p)
            assert len(w._pending_ops) == 0


def test_recv_ex_error_path():
    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        mock_dll.WinDivertOpen.return_value = 123
        mock_dll.WinDivertRecvEx.side_effect = OSError(None, "Not Pending", None, 1234)

        w = pydivert.WinDivert()
        w._handle = 123
        with pytest.raises(OSError):
            w.recv_ex()


def test_send_ex_error_path():
    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        mock_dll.WinDivertOpen.return_value = 123
        mock_dll.WinDivertSendEx.side_effect = OSError(None, "Not Pending", None, 1234)

        w = pydivert.WinDivert()
        w._handle = 123
        raw = bytearray(b"\x45" + b"\x00" * 19)
        p = Packet(raw)
        with pytest.raises(OSError):
            w.send_ex(p)


def test_packet_is_checksum_valid_udp():
    # IPv4 + UDP
    raw = bytearray(
        b"\x45\x00\x00\x1c"  # IPv4
        b"\x00\x01\x00\x00"
        b"\x40\x11\x00\x00"  # UDP (17 = 0x11)
        b"\x7f\x00\x00\x01"  # 127.0.0.1
        b"\x7f\x00\x00\x01"
        b"\x12\x34\x12\x35"  # Source port, Destination port
        b"\x00\x08\x00\x00"  # Length 8, Checksum 0
    )
    p = Packet(raw)
    assert not p.is_checksum_valid

    # Mock WinDivertHelperCalcChecksums to return success
    with patch("pydivert.windivert_dll.WinDivertHelperCalcChecksums", return_value=1):
        assert p.is_checksum_valid  # other.udp.cksum = 0 is hit here in is_checksum_valid


def test_ip_packet_len_direct_access():
    from pydivert.packet.ip import IPv4Header

    raw = bytearray(b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01")
    p = Packet(raw)
    header = IPv4Header(p)
    assert header.packet_len == 20


def test_windivert_dll_set_last_error_no_windll():
    from pydivert import windivert_dll

    with patch("pydivert.windivert_dll.windll", None):
        # Should return None instead of calling windll.kernel32.SetLastError
        assert windivert_dll.SetLastError(0) is None


@pytest.mark.asyncio
async def test_recv_async_cancellation():
    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        mock_dll.WinDivertOpen.return_value = 123
        mock_dll.CreateEventW.return_value = 456
        mock_dll.ERROR_IO_PENDING = 997
        # Simulate pending IO
        mock_dll.WinDivertRecvEx.return_value = False
        mock_dll.GetLastError.return_value = 997  # ERROR_IO_PENDING
        mock_dll.WinError.side_effect = lambda code: OSError(None, "Mocked WinError", None, code)

        with patch("asyncio.get_running_loop") as mock_loop:
            loop = MagicMock()
            mock_loop.return_value = loop

            async with pydivert.WinDivert() as w:
                fut = asyncio.Future()
                loop.run_in_executor.return_value = fut

                task = asyncio.create_task(w.recv_async())
                await asyncio.sleep(0.05)
                # Cancel the future returned by run_in_executor
                fut.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert len(w._pending_ops) == 1


@pytest.mark.asyncio
async def test_send_async_cancellation():
    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        mock_dll.WinDivertOpen.return_value = 123
        mock_dll.CreateEventW.return_value = 456
        mock_dll.ERROR_IO_PENDING = 997
        # Simulate pending IO
        mock_dll.WinDivertSendEx.return_value = False
        mock_dll.GetLastError.return_value = 997  # ERROR_IO_PENDING
        mock_dll.WinError.side_effect = lambda code: OSError(None, "Mocked WinError", None, code)

        with patch("asyncio.get_running_loop") as mock_loop:
            loop = MagicMock()
            mock_loop.return_value = loop

            async with pydivert.WinDivert() as w:
                fut = asyncio.Future()
                loop.run_in_executor.return_value = fut

                raw = bytearray(b"\x45" + b"\x00" * 39)
                p = Packet(raw)
                assert p.ipv4 is not None
                p.ipv4.packet_len = 40
                task = asyncio.create_task(w.send_async(p))
                await asyncio.sleep(0.05)
                # Cancel the future
                fut.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert len(w._pending_ops) == 1


def test_send_ex_sync_success():
    with patch("pydivert.windivert.windivert_dll") as mock_dll:
        mock_dll.WinDivertOpen.return_value = 123
        mock_dll.WinDivertSendEx.return_value = True

        w = pydivert.WinDivert()
        w._handle = 123
        p = Packet(bytearray(b"\x45" + b"\x00" * 19))
        assert w.send_ex(p) == 0  # send_len.value


def test_ip_header_base_packet_len():
    from pydivert.packet.ip import IPHeader

    p = Packet(bytearray(b"\x00" * 20))
    header = IPHeader(p)
    assert header.packet_len == 20


def test_windivert_is_registered_coverage():
    with patch("pydivert.service.is_registered", return_value=True):
        assert pydivert.WinDivert.is_registered() is True
