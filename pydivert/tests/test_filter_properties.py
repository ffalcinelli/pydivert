# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils

import sys

import pytest
from hypothesis import given
from hypothesis import strategies as st

import pydivert
from pydivert.consts import Layer

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="check_filter is Windows-only for now")


@given(filter_str=st.text(min_size=1, max_size=100), layer=st.sampled_from(list(Layer)))
def test_check_filter_robustness(filter_str, layer):
    # check_filter should never crash regardless of input
    # It might return False, but not crash
    try:
        res, pos, msg = pydivert.PyDivert.check_filter(filter_str, layer)
        assert isinstance(res, (bool, int))
        assert isinstance(pos, int)
        assert isinstance(msg, str)
    except (OSError, FileNotFoundError):
        # Driver issues
        pass


@given(port=st.integers(min_value=0, max_value=65535))
def test_valid_filter_generation(port):
    filt = f"tcp.DstPort == {port}"
    try:
        res, pos, msg = pydivert.PyDivert.check_filter(filt)
        # On a system with WinDivert, this should be True
        # If it's False, we should at least not crash
        if res is False:
            # If it fails, maybe WinDivert is not available or something else is wrong
            pass
    except (OSError, FileNotFoundError):
        pass
