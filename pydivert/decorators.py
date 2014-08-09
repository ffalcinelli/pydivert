# -*- coding: utf-8 -*-
# Copyright (C) 2014  Fabio Falcinelli
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from contextlib import contextmanager
import ctypes
import functools
import os

__author__ = 'fabio'
#0      Success
#997    Overlapped I/O is in progress
SUCCESS_RETCODES = (0, 997)


def winerror_on_retcode(funct):
    """
    This decorator throws WinError whenever the return code of last executed command is not 0 or 997
    """

    @functools.wraps(funct)
    def wrapper(instance, *args, **kwargs):
        result = funct(instance, *args, **kwargs)
        retcode = ctypes.GetLastError()
        if retcode not in SUCCESS_RETCODES:
            raise ctypes.WinError(code=retcode)
        return result

    return wrapper

    # def require_admin_rights(funct):
    #     """
    #     Check if the user has the Administrator access rights to load the driver.
    #     """
    #
    #     def wrapper(instance, *args, **kwargs):
    #         try:
    #             admin = os.getuid() == 0
    #             if not admin:
    #                 raise Exception("Root privileges required")
    #         except AttributeError as e:
    #             admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    #             if not admin:
    #                 raise ctypes.WinError(code=5, descr=ctypes.FormatError(5))
    #         else:
    #             return funct(instance, *args, **kwargs)
    #
    #     return wrapper
    #
    #


@contextmanager
def cd(path):
    """
    A context manager for a temporary change of the working directory
    """
    old_dir = os.getcwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(old_dir)
