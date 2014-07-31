import os
from zipfile import ZipFile
import sys
import shutil
import subprocess

import requests

from pydivert import python_isa, system_isa
from pydivert.decorators import cd
from pydivert.windivert import WinDivert


__author__ = 'fabio'


class WinDivertInstaller:
    """
    Installer class for WinDivert
    """

    def __init__(self, options=None, inst_dir=os.path.join(sys.exec_prefix, "DLLs")):
        if not options or "url" not in options.keys():
            raise ValueError("Invalid options passed: at least url key must be specified.")
        self.url = options["url"] % options
        self.tarball, self.pkg_name = None, None
        self.inst_dir = inst_dir

    @classmethod
    def download(cls, url):
        """
        Downloads the tarball at the given URL
        :param url: The tarball's URL
        :return: The local filename where to find the tarball
        """
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
        :param tarball: The package to uncompress
        :return: The package without extension
        """
        sys.stdout.write("Uncompressing %s...\n" % tarball)
        with ZipFile(tarball, 'r') as zip_fd:
            zip_fd.extractall()
        return os.path.splitext(tarball)[0]


    @classmethod
    def check_driver_path(cls, path):
        """
        Checks driver registration after installation
        :param path: The path where is expected to find the WinDivert.dll
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

    def uninstall(self, *args):
        """
        Removes any WinDivert artifact copied into python's DLLs directory.
        Tries to stop services and to delete them too, the deletion is required for
        WinDivert 1.0.x version only.
        :param args: a list of versions to try to uninstall, if no one is provided will try to stop only
        1.1 and 1.0
        """
        versions = args
        if not versions:
            versions = ("1.0", "1.1")
        for version in versions:
            with open(os.devnull, 'wb') as devnull:
                sys.stdout.write("Stopping service for version %s\n" % version)
                subprocess.call(['sc', 'stop', 'WinDivert%s' % version], stdout=devnull, stderr=devnull)
                subprocess.call(['sc', 'delete', 'WinDivert%s' % version], stdout=devnull, stderr=devnull)
        for item in os.listdir(self.inst_dir):
            name, ext = os.path.splitext(item)
            if name.lower() in ("windivert",
                                "windivert32",
                                "windivert64") and ext.lower() in (".sys", ".dll"):
                item = os.path.join(self.inst_dir, item)
                sys.stdout.write("Uninstalling %s...\n" % item)
                os.remove(item)

    def run(self, workdir=None):
        """
        Runs the installer
        :param workdir: The working directory to use to put tarball and uncompressed files.
        """
        with cd(workdir):
            self.tarball = self.download(self.url)
            self.pkg_name = self.unzip(self.tarball)

            dll_file = os.path.join(workdir, self.pkg_name, python_isa, "WinDivert.dll")
            sys_file = os.path.join(workdir, self.pkg_name, system_isa, "WinDivert%d.sys" % (
                64 if system_isa == "amd64" else 32))

            for f in (dll_file, sys_file):
                sys.stdout.write("Copying %s to %s\n" % (f, self.inst_dir))
                shutil.copy(f, self.inst_dir)

            sys.stdout.write("Trying to register driver...\n")
            self.check_driver_path(os.path.join(self.inst_dir, "WinDivert.dll"))

            sys.stdout.write("Cleaning paths...\n")
            self.clean()
