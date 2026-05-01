# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys
import pytest
import pydivert
from pydivert.consts import Layer, Flag

def test_windivert_legacy_instantiation():
    """
    Verifies that pydivert.WinDivert can still be instantiated directly.
    """
    if sys.platform == "win32":
        try:
            w = pydivert.WinDivert(filter="false", layer=Layer.NETWORK)
            assert isinstance(w, pydivert.WinDivert)
            assert w.filter == "false"
            # We don't necessarily open it here to avoid needing admin rights for a simple instantiation test
            # but we verify the properties are set.
        except Exception as e:
            pytest.fail(f"WinDivert instantiation failed on Windows: {e}")
    else:
        # On Linux, WinDivert should either not be importable (unlikely given our __init__.py)
        # or it should fail upon usage or instantiation if it's strictly Windows-only.
        # According to our plan, it should raise NotImplementedError or OSError.
        with pytest.raises((NotImplementedError, OSError)):
            pydivert.WinDivert()

def test_ebpf_divert_availability():
    """
    Verifies that EBPFDivert is available on Linux and behaves correctly on Windows.
    """
    if sys.platform.startswith("linux"):
        try:
            from pydivert.ebpf import EBPFDivert
            # Instantiation might fail if libbpf is missing, which is acceptable for an availability test
            # but the class should exist.
            assert EBPFDivert is not None
        except ImportError:
            pytest.skip("libbpf or EBPFDivert not available")
    else:
        with pytest.raises((NotImplementedError, ImportError, OSError)):
            from pydivert.ebpf import EBPFDivert
            EBPFDivert()

def test_facade_routing():
    """
    Verifies that Divert routes to the correct implementation.
    """
    w = pydivert.Divert("false")
    if sys.platform == "win32":
        assert w._impl.__class__.__name__ == "WinDivert"
    elif sys.platform.startswith("linux"):
        assert w._impl.__class__.__name__ == "EBPFDivert"
    else:
        with pytest.raises(NotImplementedError):
            pydivert.Divert()
