import sys
import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="WinDivert only supported on Windows")

import pydivert


@pytest.mark.asyncio
async def test_async_context_manager():
    # We use "false" to avoid capturing real traffic and requiring Admin in some environments,
    # though WinDivertOpen usually requires Admin anyway.
    try:
        async with pydivert.WinDivert("false") as w:
            assert w.is_open
    except (PermissionError, OSError):
        pytest.skip("Test requires administrator privileges.")


@pytest.mark.asyncio
async def test_async_iteration():
    try:
        async with pydivert.WinDivert("false") as w:
            # We don't actually iterate as it would block, but we check if it's an aiter
            assert hasattr(w, "__aiter__")
            assert hasattr(w, "__anext__")
    except (PermissionError, OSError):
        pytest.skip("Test requires administrator privileges.")


@pytest.mark.asyncio
async def test_recv_send_async():
    try:
        async with pydivert.WinDivert("false") as w:
            # We can't easily test a real recv without traffic, but we can check the methods exist
            assert hasattr(w, "recv_async")
            assert hasattr(w, "send_async")
    except (PermissionError, OSError):
        pytest.skip("Test requires administrator privileges.")
