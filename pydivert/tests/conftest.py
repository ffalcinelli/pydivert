import pytest

from pydivert.tests.util import check_availability


@pytest.fixture(autouse=True)
def check_pydivert_availability(request):
    # Only run this check for integration tests (those not using mocks)
    if "mock" in request.node.name or "mock" in request.node.nodeid:
        return

    # Optional: use a marker to trigger availability check
    if request.node.get_closest_marker("integration"):
        check_availability()
