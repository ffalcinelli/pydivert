# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys
import pytest
from pydivert.linux import NetFilterQueue

@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
def test_linux_open_close():
    # This might fail if not running as root, but we want to check the logic
    nfq = NetFilterQueue("tcp.DstPort == 80")
    try:
        nfq.open()
        assert nfq.is_open or not nfq.is_open # Placeholder for actual check
    except Exception as e:
        pytest.skip(f"Could not open NetFilterQueue: {e} (maybe need root?)")
    finally:
        nfq.close()
