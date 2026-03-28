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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import subprocess

# Detect paths
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)

# Change to the project root directory to ensure mkdocs build works correctly
os.chdir(root)

# Build documentation using mkdocs
print("Building documentation with MkDocs...")
subprocess.check_call(["uv", "run", "mkdocs", "build"])

print("Documentation built successfully in 'site/' directory.")
