import sys
from unittest.mock import MagicMock, patch

import pytest

import pydivert


def test_divert_kwargs_ignored_by_backend():
    """Test that arbitrary kwargs don't crash the Divert constructor."""
    try:
        # We don't open it, just create the object
        d = pydivert.Divert(filter="false", unknown_option="value")
        assert d is not None
    except TypeError as e:
        pytest.fail(f"Divert raised TypeError with unknown kwargs: {e}")


@pytest.mark.skipif(sys.platform != "linux", reason="eBPF only on Linux")
def test_ebpf_interfaces_option():
    """Test that EBPFDivert respects the 'interfaces' option."""
    from pydivert.ebpf import EBPFDivert

    mock_libbpf = MagicMock()
    mock_libbpf.bpf_object__open_file.return_value = MagicMock()
    mock_libbpf.bpf_object__load.return_value = 0
    # Success for TC hook operations
    mock_libbpf.bpf_tc_hook_destroy.return_value = 0
    mock_libbpf.bpf_tc_hook_create.return_value = 0
    mock_libbpf.bpf_tc_attach.return_value = 0

    with (
        patch("pydivert.ebpf.libbpf", mock_libbpf),
        patch("socket.if_nameindex", return_value=[(1, "lo"), (2, "eth0"), (3, "eth1")]),
    ):
        # Test with specific interface
        d = EBPFDivert(filter="true", interfaces=["eth0"])

        with patch.object(d, "_ring_callback", MagicMock()):
            d._open_impl()

        # Each interface gets 2 hooks (ingress/egress)
        # Since we specified ["eth0"], only eth0 should be hooked
        assert len(d._hooks) == 2


@pytest.mark.skipif(sys.platform != "linux", reason="eBPF only on Linux")
def test_ebpf_no_interfaces_option():
    """Test that EBPFDivert uses all interfaces by default."""
    from pydivert.ebpf import EBPFDivert

    mock_libbpf = MagicMock()
    mock_libbpf.bpf_object__open_file.return_value = MagicMock()
    mock_libbpf.bpf_object__load.return_value = 0
    # Success for TC hook operations
    mock_libbpf.bpf_tc_hook_destroy.return_value = 0
    mock_libbpf.bpf_tc_hook_create.return_value = 0
    mock_libbpf.bpf_tc_attach.return_value = 0

    with (
        patch("pydivert.ebpf.libbpf", mock_libbpf),
        patch("socket.if_nameindex", return_value=[(1, "lo"), (2, "eth0")]),
    ):
        d = EBPFDivert(filter="true")

        with patch.object(d, "_ring_callback", MagicMock()):
            d._open_impl()

        # 2 interfaces * 2 hooks = 4 hooks
        assert len(d._hooks) == 4
