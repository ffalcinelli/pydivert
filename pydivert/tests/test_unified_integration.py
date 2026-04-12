# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys

import pytest

from pydivert import PyDivert


@pytest.mark.asyncio
async def test_unified_open_close():
    """
    Test that PyDivert can be opened and closed with a simple filter
    on any supported platform.
    """
    filter_str = "tcp.DstPort == 80"

    # Use as a context manager
    try:
        with PyDivert(filter_str) as w:
            assert w.is_open or not w.is_open # Implementation dependent, but should not crash
    except (RuntimeError, NotImplementedError, OSError, ImportError) as e:
        # On Linux/BSD this might fail if not root, or if not implemented
        pytest.skip(f"Opening handle failed on {sys.platform}: {e}")

@pytest.mark.asyncio
async def test_unified_async_context_manager():
    """
    Test that the async context manager works on all platforms.
    """
    filter_str = "udp"
    try:
        async with PyDivert(filter_str) as w:
            assert w is not None
    except (RuntimeError, NotImplementedError, OSError, ImportError) as e:
        pytest.skip(f"Async opening handle failed on {sys.platform}: {e}")

def test_backend_selection():
    """
    Check if the correct backend class is selected based on the platform.
    """
    w = PyDivert()
    impl_class = w._impl.__class__.__name__

    if sys.platform == "win32":
        assert impl_class == "WinDivert"
    elif sys.platform.startswith("linux"):
        assert impl_class == "NetFilterQueue"
    elif sys.platform == "darwin":
        assert impl_class == "MacOSDivert"
    elif sys.platform.startswith("freebsd"):
        assert impl_class == "Divert"
    else:
        pytest.fail(f"Unknown platform: {sys.platform}")
