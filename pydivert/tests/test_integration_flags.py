import pytest

from pydivert import Flag, WinDivert


def test_intflag_combinations():
    flags = Flag.SNIFF | Flag.FRAGMENTS
    assert flags.value == 33
    assert Flag.SNIFF in flags
    assert Flag.FRAGMENTS in flags

    # Test initialization with combined flags. Note: We use "false" to not capture real traffic.
    # We just want to ensure the constructor accepts it and passes it to the DLL without crashing.
    # Depending on permissions this might raise PermissionError or OSError.
    # We handle the permissions error gracefully.
    try:
        w = WinDivert("false", flags=flags)
        w.open()
        w.close()
    except PermissionError:
        pytest.skip("Test requires administrator privileges to open WinDivert handle.")
    except OSError as e:
        if getattr(e, "winerror", None) == 5:  # ERROR_ACCESS_DENIED
            pytest.skip("Test requires administrator privileges to open WinDivert handle.")
        elif getattr(e, "winerror", None) == 2:  # ERROR_FILE_NOT_FOUND (driver missing on linux)
            pytest.skip("WinDivert driver is not installed (expected on Linux).")
        else:
            pytest.fail(f"WinDivert failed with combined flags: {e}")
