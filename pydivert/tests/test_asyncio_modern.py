import pytest

import pydivert
from pydivert.tests.util import check_availability


@pytest.fixture(autouse=True)
def require_pydivert():
    check_availability()


@pytest.mark.asyncio
async def test_async_context_manager():
    async with pydivert.PyDivert("false") as w:
        assert w.is_open


@pytest.mark.asyncio
async def test_async_iteration():
    async with pydivert.PyDivert("false") as w:
        # We don't actually iterate as it would block, but we check if it's an aiter
        assert hasattr(w, "__aiter__")
        assert hasattr(w, "__anext__")


@pytest.mark.asyncio
async def test_recv_send_async():
    async with pydivert.PyDivert("false") as w:
        # We can't easily test a real recv without traffic, but we can check the methods exist
        assert hasattr(w, "recv_async")
        assert hasattr(w, "send_async")
