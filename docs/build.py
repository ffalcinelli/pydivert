import os
import subprocess
import shutil

# Detect paths
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)

# Change to the project root directory to ensure mkdocs build works correctly
os.chdir(root)

# Build documentation using mkdocs
print("Building documentation with MkDocs...")
subprocess.check_call(["uv", "run", "mkdocs", "build"])

print("Documentation built successfully in 'site/' directory.")
