# -*- coding: utf-8 -*-
# Copyright (C) 2016  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import sys


class cached_property(object):
    """
    A property that is only computed once per instance and then replaces itself
    with an ordinary attribute. Deleting the attribute resets the property.
    Source: https://github.com/bottlepy/bottle/commit/fa7733e075da0d790d809aa3d2f53071897e6f76
    """

    def __init__(self, func):
        self.__doc__ = getattr(func, '__doc__')
        self.func = func

    def __get__(self, obj, cls):
        if obj is None:  # pragma: no cover
            return self
        value = obj.__dict__[self.func.__name__] = self.func(obj)
        return value


if sys.version_info < (3, 0):
    # python 3's byte indexing: b"AAA"[1] == 65
    indexbyte = lambda x: chr(x) if isinstance(x, int) else ord(x)
    # python 3's bytes.fromhex()
    fromhex = lambda x: x.decode("hex")
    PY2 = True
    PY34 = False
else:
    indexbyte = lambda x: x
    fromhex = lambda x: bytes.fromhex(x)
    PY2 = False
    if sys.version_info < (3, 5):
        # __doc__ attribute is only writable from 3.5.
        PY34 = True
    else:
        PY34 = False
