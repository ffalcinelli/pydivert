import pytest


@pytest.fixture(autouse=True)
def check_pydivert_availability(request):
    # Only run this check for tests that require PyDivert integration
    # We can check markers or just try to open it for tests that need it.
    pass
