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

import time

from pydivert import PyDivert, service


def test_is_registered_direct():
    # Test the service module directly
    reg = service.is_registered()
    assert isinstance(reg, bool)


def test_register():
    # Clean state
    if PyDivert.is_registered():
        PyDivert.unregister()

    # Wait for stop
    timeout = 5.0
    start = time.time()
    while PyDivert.is_registered() and time.time() - start < timeout:
        time.sleep(0.1)

    assert not PyDivert.is_registered()

    # Register (triggers when opening a handle)
    with PyDivert("false") as w:
        assert w.is_open
        assert PyDivert.is_registered()

    assert PyDivert.is_registered()


def test_unregister():
    # Ensure registered
    if not PyDivert.is_registered():
        PyDivert.register_service()

    assert PyDivert.is_registered()

    PyDivert.unregister()

    # Wait for stop
    timeout = 5.0
    start = time.time()
    while PyDivert.is_registered() and time.time() - start < timeout:
        time.sleep(0.1)

    # unregister only requests stop, might still be registered if handles are open
    # but in this test we don't have open handles.
    assert not PyDivert.is_registered()
