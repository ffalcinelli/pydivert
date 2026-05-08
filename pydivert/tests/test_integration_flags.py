import pytest

from pydivert import Divert, Flag


def test_intflag_combinations():
    flags = Flag.SNIFF | Flag.FRAGMENTS
    assert Flag.SNIFF in flags
    assert Flag.FRAGMENTS in flags

    # Test initialization with combined flags. Note: We use "false" to not capture real traffic.
    # We just want to ensure the constructor accepts it and it works.
    try:
        w = Divert("false", flags=flags)
        w.open()
        w.close()
    except (PermissionError, OSError) as e:
        pytest.skip(f"Could not open handle: {e}")
