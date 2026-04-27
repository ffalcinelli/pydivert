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

"""
.. include:: ../README.md
.. include:: ../docs/FILTER_LANGUAGE.md
.. include:: ../SECURITY.md

---
"""

import sys

from .consts import CalcChecksumsOption, Direction, Flag, Layer, Param, Protocol, RecvFlag
from .packet import Packet
from .pydivert import PyDivert

WinDivert = None
NetFilterQueue = None
MacOSDivert = None
Divert = None

if sys.platform == "win32":
    from .windivert import WinDivert
elif sys.platform.startswith("linux"):
    from .linux import NetFilterQueue
elif sys.platform == "darwin":
    from .macos import MacOSDivert
    from .bsd import Divert  # macOS also uses BSD-style divert sockets
elif sys.platform.startswith("freebsd"):
    from .bsd import Divert

__author__ = "fabio"
__version__ = "4.0.0"

__all__ = [
    "PyDivert",
    "WinDivert",
    "NetFilterQueue",
    "Divert",
    "MacOSDivert",
    "Packet",
    "Layer",
    "Flag",
    "Param",
    "CalcChecksumsOption",
    "Direction",
    "Protocol",
    "RecvFlag",
]
