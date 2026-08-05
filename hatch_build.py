import os
import subprocess
import sys

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        """
        This hook is called before the build process starts.
        We use it to fetch the necessary binaries.
        """
        print("Initializing build: fetching external binaries...")
        script_path = os.path.join(self.root, "scripts", "fetch_binaries.py")

        # Run the fetch script using the current Python interpreter
        result = subprocess.run([sys.executable, script_path], check=False)

        if result.returncode != 0:
            print("Warning: Failed to fetch binaries. Build might be incomplete.")
        else:
            print("Successfully initialized build with external binaries.")

        # Ensure the binaries are included in the build
        # Hatchling includes everything in 'packages' by default,
        # but since these are downloaded and possibly ignored by git,
        # we might need to explicitly tell Hatch to include them if they aren't in 'packages'.
        # However, pydivert/windivert_dll and pydivert/bpf ARE in the 'pydivert' package.
