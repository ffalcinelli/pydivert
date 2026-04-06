# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
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
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import shutil
import subprocess

# Detect paths
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)

# Change to the project root directory to ensure pdoc build works correctly
os.chdir(root)

# Build documentation using pdoc
print("Building documentation with pdoc...")
subprocess.run(["uv", "run", "pdoc", "pydivert", "-o", "site"], check=True)

# Copy license and security files to site directory to fix broken links in README
print("Copying extra files to site/ directory...")
for extra_file in ["LICENSE", "LICENSE-GPL-2.0-or-later", "LICENSE-LGPL-3.0-or-later", "SECURITY.md"]:
    if os.path.exists(extra_file):
        shutil.copy(extra_file, "site/")

print("Documentation built successfully in 'site/' directory.")
