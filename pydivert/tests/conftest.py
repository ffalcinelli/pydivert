import sys

import pydivert


def pytest_runtest_setup(item):
    if sys.platform.startswith("linux"):
        # Ensure clean state for every test on Linux eBPF
        try:
            pydivert.Divert.unregister()
        except Exception:
            pass


def pytest_runtest_teardown(item, nextitem):
    if sys.platform.startswith("linux"):
        # Clean up after every test
        try:
            pydivert.Divert.unregister()
        except Exception:
            pass
