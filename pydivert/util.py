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
# see <http://www.gnu.org/licenses/>.

import struct


class cached_property:
    """
    A property that is only computed once per instance and then replaces itself
    with an ordinary attribute. Deleting the attribute resets the property.
    Source: https://github.com/bottlepy/bottle/commit/fa7733e075da0d790d809aa3d2f53071897e6f76
    """

    def __init__(self, func):
        self.__doc__ = func.__doc__
        self.func = func

    def __get__(self, obj, cls):
        if obj is None:  # pragma: no cover
            return self
        value = obj.__dict__[self.func.__name__] = self.func(obj)
        return value


def fromhex(x):
    return bytes.fromhex(x)


def flag_property(name, offset, bit, docs=None):
    @property
    def flag(self):
        return bool(self.raw[offset] & bit)

    @flag.setter
    def flag(self, val):
        flags = self.raw[offset]
        if val:
            flags |= bit
        else:
            flags &= ~bit
        self.raw[offset] = flags

    flag.__doc__ = (
        f"""
        Indicates if the {name.upper()} flag is set.
        """
        if not docs
        else docs
    )

    return flag  # type: ignore[misc]


def raw_property(fmt, offset, docs=None):
    @property
    def rprop(self):
        return struct.unpack_from(fmt, self.raw, offset)[0]

    @rprop.setter
    def rprop(self, val):
        struct.pack_into(fmt, self.raw, offset, val)

    if docs:
        rprop.__doc__ = docs

    return rprop  # type: ignore[misc]
