import os
import platform
import subprocess
import sys

from hatchling.builders.hooks.plugin.interface import BuildHookInterface  # type: ignore

# Wheel platform tag -> what scripts/fetch_binaries.py must bundle.
TARGETS = {
    "win_amd64": {"PYDIVERT_TARGET": "win_amd64"},
    "manylinux_2_28_x86_64": {"PYDIVERT_TARGET": "linux", "PYDIVERT_TARGET_ARCH": "amd64"},
    "manylinux_2_28_aarch64": {"PYDIVERT_TARGET": "linux", "PYDIVERT_TARGET_ARCH": "arm64"},
}


def _host_target() -> str:
    if sys.platform == "win32":
        return "win_amd64"
    machine = platform.machine().lower()
    return "manylinux_2_28_aarch64" if machine in ("aarch64", "arm64") else "manylinux_2_28_x86_64"


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        """
        Fetch the native library of the target platform and tag the wheel.

        Wheels are platform specific: WinDivert (Windows) or the
        self-contained libebpfdivert.so (Linux, per architecture).  Set
        PYDIVERT_TARGET to one of TARGETS to cross-build, e.g.
        ``PYDIVERT_TARGET=win_amd64 uv build --wheel``.
        """
        if self.target_name != "wheel":
            return

        target = os.environ.get("PYDIVERT_TARGET") or _host_target()
        if target not in TARGETS:
            raise ValueError(f"PYDIVERT_TARGET must be one of {sorted(TARGETS)}, got {target!r}")

        print(f"Initializing {target} build: fetching native binaries...")
        script_path = os.path.join(self.root, "scripts", "fetch_binaries.py")
        if version == "editable":
            # Development checkout: fetch the host's binaries without deleting
            # other platforms' (the tree may be shared with a VM).
            env = {k: v for k, v in os.environ.items() if k not in ("PYDIVERT_TARGET", "PYDIVERT_TARGET_ARCH")}
        else:
            env = dict(os.environ, **TARGETS[target])
        result = subprocess.run([sys.executable, script_path], check=False, env=env)
        if version == "editable":
            # Development install: binaries can also be provided later
            # (scripts/fetch_binaries.py or PYDIVERT_EBPFDIVERT_LOCAL).
            if result.returncode != 0:
                print("Warning: native binaries not fetched; the installation is incomplete.")
            return
        if result.returncode != 0:
            raise RuntimeError("Failed to fetch native binaries for the wheel.")

        build_data["pure_python"] = False
        build_data["tag"] = f"py3-none-{target}"
