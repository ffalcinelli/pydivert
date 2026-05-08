# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of either:
#
# 1) The GNU Lesser General Public License as published by the Free
#    Software Foundation, either version 3 of the License, or (at your
#    option) any later version.
#
# 2) The GNU General Public License as published by the Free Software
#    Foundation, either version 2 of the License, or (at your option)
#    any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License and the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# and the GNU General Public License along with this program.  If not,
# see <https://www.gnu.org/licenses/>.

import sys
import time

import pytest

from pydivert import Divert, service


def test_is_registered_direct():
    # Test the service module directly
    reg = service.is_registered()
    assert isinstance(reg, bool)


@pytest.mark.skipif(sys.platform != "win32", reason="Driver registration is Windows-specific")
def test_register():
    # Clean state
    if Divert.is_registered():
        Divert.unregister()

    # Wait for stop
    timeout = 5.0
    start = time.time()
    while Divert.is_registered() and time.time() - start < timeout:
        time.sleep(0.1)

    assert not Divert.is_registered()

    # Register (triggers when opening a handle)
    with Divert("false") as w:
        assert w.is_open
        assert Divert.is_registered()

    assert Divert.is_registered()


@pytest.mark.skipif(sys.platform != "win32", reason="Driver registration is Windows-specific")
def test_unregister():
    # Ensure registered
    if not Divert.is_registered():
        Divert.register_service()

    assert Divert.is_registered()

    Divert.unregister()

    # Wait for stop
    timeout = 5.0
    start = time.time()
    while Divert.is_registered() and time.time() - start < timeout:
        time.sleep(0.1)

    # unregister only requests stop, might still be registered if handles are open
    # but in this test we don't have open handles.
    assert not Divert.is_registered()
