#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2016  Fabio Falcinelli
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
import os
import site

from pydivert.decorators import cd
from pydivert.install import WinDivertInstaller


__author__ = 'fabio'

from setuptools import setup, find_packages, Command
from setuptools.command.install import install as _install

workdir = os.path.abspath(os.path.dirname(__file__))

windivert = {
    "version": "1.1.8",
    "compiler": "WDDK",  # MSVC | MINGW
    "url": "https://github.com/basil00/Divert/releases/download/v%(version)s/WinDivert-%(version)s-%(compiler)s.zip"
}


class install(_install):
    description = 'Installs pydivert package and the windivert driver'

    def run(self):
        windivert_installer = WinDivertInstaller(windivert)
        _install.run(self)
        self.execute(windivert_installer.run, (self.install_lib,),
                     msg="Running WinDivert install task")


class InstallDriver(Command):
    description = 'Installs the windivert driver'
    user_options = []
    extra_env = {}
    extra_args = []

    def run(self):
        windivert_installer = WinDivertInstaller(windivert)
        self.execute(windivert_installer.run, (site.getsitepackages()[0],),
                     msg="Running WinDivert uninstall task")

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass


class UninstallDriver(Command):
    description = 'Uninstalls the windivert driver'
    user_options = []
    extra_env = {}
    extra_args = []

    def run(self):
        windivert_installer = WinDivertInstaller(windivert)
        self.execute(windivert_installer.uninstall, [],
                     msg="Running WinDivert uninstall task")

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass


class RunTests(Command):
    description = 'Runs the test suite for pydivert'
    user_options = []
    extra_env = {}
    extra_args = []

    def run(self):
        from pydivert.tests import run_test_suites

        for env_name, env_value in self.extra_env.items():
            os.environ[env_name] = str(env_value)

        with cd(os.path.join(os.path.join(workdir, "pydivert", "tests"))):
            run_test_suites()

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass


options = dict(name='pydivert',
               version='0.0.8',
               description='Python binding to windivert driver',
               # long_description=readme.read(),
               author='Fabio Falcinelli',
               author_email='fabio.falcinelli@gmail.com',
               url='https://github.com/ffalcinelli/pydivert',
               download_url='https://github.com/ffalcinelli/pydivert/tarball/%(version)s',
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
               extras_require={
                   "testing": ["mock>=1.0.1"]
               },
               cmdclass={
                   "install": install,
                   "wd_uninstall": UninstallDriver,
                   "wd_install": InstallDriver,
                   "test": RunTests
               }, )

options["download_url"] = options["download_url"] % options

setup(**options)
