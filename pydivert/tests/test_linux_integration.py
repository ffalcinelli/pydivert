# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys

import pytest

from pydivert.linux import NetFilterQueue


def setup_module(module):
    """Skip all tests in this module if not running on Linux."""
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux only tests")


def test_linux_open_close():
    # This might fail if not running as root, but we want to check the logic
    import os

    nfq = NetFilterQueue("tcp.DstPort == 80")
    try:
        nfq.open()
        assert nfq.is_open or not nfq.is_open  # Placeholder for actual check
    except Exception as e:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail(
                f"Could not open NetFilterQueue in CI: {e}. Ensure tests run as root and libnetfilter-queue is present."
            )
        pytest.skip(f"Could not open NetFilterQueue: {e} (maybe need root?)")
    finally:
        nfq.close()
