#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2013  Fabio Falcinelli
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
import os
from pydivert.tests import run_test_suites

__author__ = 'fabio'

from setuptools import setup, find_packages, Command

workdir = os.path.abspath(os.path.dirname(__file__))


class RunTests(Command):
    description = 'Runs the test suite for audit4llc'
    user_options = []
    extra_env = {}
    extra_args = []

    def run(self):
        for env_name, env_value in self.extra_env.items():
            os.environ[env_name] = str(env_value)
        cwd = os.getcwd()
        try:
            os.chdir(os.path.join(os.path.join(workdir, "pydivert", "tests")))
            run_test_suites()
        finally:
            os.chdir(cwd)

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass


setup(name='pydivert',
      version='0.0.2',
      description='Python binding to windivert driver',
      # long_description=readme.read(),
      author='Fabio Falcinelli',
      author_email='fabio.falcinelli@gmail.com',
      url='https://github.com/ffalcinelli/pydivert',
      download_url='https://github.com/ffalcinelli/pydivert/tarball/0.0.2',
      keywords=['windivert', 'network', 'tcp/ip'],
      license="LICENSE",
      packages=find_packages(),
      classifiers=[
          'Development Status :: 2 - Pre-Alpha',
          'Environment :: Win32 (MS Windows)',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'Intended Audience :: Telecommunications Industry',
          'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
          'Operating System :: Microsoft :: Windows :: Windows Vista',
          'Operating System :: Microsoft :: Windows :: Windows Server 2008',
          'Operating System :: Microsoft :: Windows :: Windows 7',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3.3',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Networking :: Firewalls',
          'Topic :: System :: Networking :: Monitoring',
          'Topic :: Utilities',
      ],
      cmdclass={"test": RunTests},
)