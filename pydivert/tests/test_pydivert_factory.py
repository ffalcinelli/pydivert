# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import sys
import pytest
from pydivert import PyDivert
from pydivert.linux import NetFilterQueue
from pydivert.filter import transpile

def test_pydivert_factory():
    if sys.platform.startswith("linux"):
        with PyDivert("tcp.DstPort == 80") as w:
            assert isinstance(w._impl, NetFilterQueue)
    else:
        pytest.skip("Test only for Linux")

def test_transpiler_basic():
    filter_str = "tcp.DstPort == 80"
    # For now it just returns the same string as we haven't implemented BPF mapping yet
    result = transpile(filter_str)
    assert result == "tcp.DstPort == 80"

def test_transpiler_complex():
    filter_str = "tcp.DstPort == 80 && (ip.SrcAddr == 127.0.0.1 || outbound)"
    result = transpile(filter_str)
    assert result == "tcp.DstPort == 80 && (ip.SrcAddr == 127.0.0.1 || outbound)"

def test_transpiler_ternary():
    filter_str = "outbound ? tcp.DstPort == 80 : tcp.SrcPort == 80"
    result = transpile(filter_str)
    assert result == "(outbound ? tcp.DstPort == 80 : tcp.SrcPort == 80)"
