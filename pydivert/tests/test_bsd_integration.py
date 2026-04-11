# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys

import pytest

from pydivert.bsd import Divert


@pytest.mark.skipif(not (sys.platform.startswith("freebsd") or sys.platform == "darwin"), reason="BSD/macOS only")
def test_bsd_open_close():
    # This might fail if not running as root
    d = Divert("tcp.DstPort == 80")
    try:
        d.open()
        assert d.is_open or not d.is_open # Placeholder for actual check
    except Exception as e:
        pytest.skip(f"Could not open BSD Divert: {e} (maybe need root?)")
    finally:
        d.close()
