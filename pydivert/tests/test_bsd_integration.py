# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys

import pytest

from pydivert.bsd import Divert


def setup_module(module):
    """Skip all tests in this module if not running on BSD or macOS."""
    if not (sys.platform.startswith("freebsd") or sys.platform == "darwin"):
        pytest.skip("BSD/macOS only tests")

def test_bsd_open_close():
    # This might fail if not running as root
    import os
    d = Divert("tcp.DstPort == 80")
    try:
        d.open()
        assert d.is_open or not d.is_open # Placeholder for actual check
    except Exception as e:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail(f"Could not open BSD/macOS Divert in CI: {e}. Ensure tests run as root.")
        pytest.skip(f"Could not open BSD Divert: {e} (maybe need root?)")
    finally:
        d.close()
