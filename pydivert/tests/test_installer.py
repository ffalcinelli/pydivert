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
import os
import shutil
import unittest

from mock import patch

from pydivert.decorators import cd
from pydivert.install import WinDivertInstaller
from pydivert.tests import FIXTURES_DIR, mock_requests_download
from pydivert.tests.test_windivert import BaseTestCase


__author__ = 'Fabio'


class InstallerBaseTestCase(unittest.TestCase):
    def setUp(self):
        self.work_dir = os.path.join(FIXTURES_DIR, "work_dir")
        # self.installer = WinDivertInstaller()
        if not os.path.exists(self.work_dir):
            os.makedirs(self.work_dir)

        self.tarball = "WinDivert-1.1.5-WDDK.zip"
        self.options = {
            "version": "1.1.5",
            "compiler": "WDDK",  # MSVC | MINGW
            "url": "https://github.com/basil00/Divert/releases/download/v%(version)s/WinDivert-%(version)s-%(compiler)s.zip"
        }


    def tearDown(self):
        if os.path.exists(self.work_dir):
            shutil.rmtree(self.work_dir)


class InstallerClassTestCase(InstallerBaseTestCase):
    @mock_requests_download()
    def test_download(self):
        """
        Tests the download of a package through WinDivertInstaller class
        :return:
        """
        with cd(self.work_dir):
            local_filename = WinDivertInstaller.download(url="http://somehost/somedir/%s" % self.tarball)
            self.assertEquals(local_filename, self.tarball)
            self.assertTrue(os.path.exists(os.path.join(self.work_dir, self.tarball)))

    def test_unzip(self):
        """
        Tests the uncompressing method of WinDivertInstaller class
        :return:
        """
        self.test_download()
        with cd(self.work_dir):
            expected_dir = os.path.join(self.work_dir, os.path.splitext(self.tarball)[0])
            extracted_dir = WinDivertInstaller.unzip(os.path.join(self.work_dir, self.tarball))
            self.assertEquals(extracted_dir, expected_dir)
            self.assertTrue(os.path.exists(expected_dir))


class InstallerInstanceTestCase(InstallerBaseTestCase):
    def setUp(self):
        super().setUp()
        self.installer = WinDivertInstaller(options=self.options, inst_dir=self.work_dir)

    def tearDown(self):
        self.installer.uninstall()
        super().tearDown()

    def test_uninstall(self):
        """
        Tests the uninstallation of WinDivert driver
        :return:
        """

        def fake_uninstall(*args, **kwargs):
            for item in os.listdir(self.work_dir):
                name, ext = os.path.splitext(item)
                if name.lower() in ("windivert",
                                    "windivert32",
                                    "windivert64") and ext.lower() in (".sys",
                                                                       ".dll"):
                    item = os.path.join(self.work_dir, item)
                    os.remove(item)

        with patch("subprocess.call", fake_uninstall):
            self.installer.uninstall()
            for item in os.listdir(self.work_dir):
                name, ext = os.path.splitext(item)
                self.assertNotIn(name.lower(), ("windivert",
                                                "windivert32",
                                                "windivert64"))
                self.assertNotIn(ext.lower(), (".sys", ".dll"))

    @mock_requests_download()
    def test_install(self):
        """
        Tests the installation of the driver. Requests is mocked to avoid a real http get
        :return:
        """
        with patch.object(self.installer, "check_driver_path", lambda *args, **kwargs: None):
            self.installer.run(workdir=self.work_dir)
            for item in os.listdir(self.work_dir):
                name, ext = os.path.splitext(item)
                self.assertIn(name.lower(), ("windivert",
                                             "windivert32",
                                             "windivert64"))
                self.assertIn(ext.lower(), (".sys", ".dll"))


class DriverRegistrationTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.options = {
            "version": "1.1.5",
            "compiler": "WDDK",  # MSVC | MINGW
            "url": "https://github.com/basil00/Divert/releases/download/v%(version)s/WinDivert-%(version)s-%(compiler)s.zip"
        }
        self.installer = WinDivertInstaller(options=self.options, inst_dir=self.driver_dir)
        self.dll_path = os.path.join(self.driver_dir, "WinDivert.dll")


    def test_driver_registration_with_installer(self):
        """
        Tests WinDivert driver installer register check
        :return:
        """
        self.assertIsNotNone(self.installer.check_driver_path(self.dll_path))