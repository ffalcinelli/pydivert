import os
from zipfile import ZipFile
import sys
import shutil

import requests

from pydivert import python_isa, system_isa
from pydivert.decorators import cd
from pydivert.windivert import WinDivert


__author__ = 'fabio'


class WinDivertInstaller:
    """
    Installer class for WinDivert
    """

    def __init__(self, options=None):
        if not options or "url" not in options.keys():
            raise ValueError("Invalid options passed: at least url key must be specified.")
        self.url = options["url"] % options
        self.tarball, self.pkg_name = None, None

    @classmethod
    def download(cls, url):

        sys.stdout.write("Downloading %s...\n" % url)
        local_filename = url.split('/')[-1]
        response = requests.get(url, stream=True)
        with open(local_filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
                    f.flush()
        return local_filename

    @classmethod
    def unzip(cls, tarball):
        """
        Uncompresses the tarball
        """
        sys.stdout.write("Uncompressing %s...\n" % tarball)
        with ZipFile(tarball, 'r') as zip_fd:
            zip_fd.extractall()
        return os.path.splitext(tarball)[0]


    @classmethod
    def check_driver_path(cls, path):
        """
        Checks driver registration after installation
        """
        try:
            WinDivert(dll_path=path).register()
        except Exception as e:
            sys.stderr.write("Driver registration failed: %s" % str(e))

    def clean(self):
        """
        Cleans tarball and uncompressed directory
        """
        if os.path.exists(self.pkg_name):
            sys.stdout.write("Removing uncompressed folder %s...\n" % self.pkg_name)
            shutil.rmtree(self.pkg_name)

        if os.path.exists(self.tarball):
            sys.stdout.write("Removing tarball %s...\n" % self.tarball)
            os.remove(self.tarball)

    def run(self, workdir=None):
        """
        Runs the installer
        """
        with cd(workdir):
            self.tarball = self.download(self.url)
            self.pkg_name = self.unzip(self.tarball)

            dll_file = os.path.join(workdir, self.pkg_name, python_isa, "WinDivert.dll")
            sys_file = os.path.join(workdir, self.pkg_name, system_isa, "WinDivert%d.sys" % (
                64 if system_isa == "amd64" else 32))

            python_dlls = os.path.join(sys.exec_prefix, "DLLs")

            for f in (dll_file, sys_file):
                sys.stdout.write("Copying %s to %s\n" % (f, python_dlls))
                shutil.copy(f, python_dlls)

            sys.stdout.write("Trying to register driver...\n")
            self.check_driver_path(os.path.join(python_dlls, "WinDivert.dll"))

            sys.stdout.write("Cleaning paths...\n")
            self.clean()
