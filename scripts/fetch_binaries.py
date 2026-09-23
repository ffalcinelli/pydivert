import io
import os
import platform
import re
import shutil
import sys
import tarfile
import urllib.request
import zipfile

# Root directory of the project
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def get_versions():
    """Reads versions from pyproject.toml without external dependencies."""
    path = os.path.join(ROOT, "pyproject.toml")
    with open(path, encoding="utf-8") as f:
        content = f.read()

    windivert = re.search(r'windivert\s*=\s*"([^"]+)"', content)
    ebpfdivert = re.search(r'ebpfdivert\s*=\s*"([^"]+)"', content)

    if not windivert or not ebpfdivert:
        raise RuntimeError("Could not find binary versions in pyproject.toml")

    return windivert.group(1), ebpfdivert.group(1)


def download_windivert(version):
    """Downloads and extracts WinDivert binaries."""
    dst_dir = os.path.join(ROOT, "pydivert", "windivert_dll")
    version_file = os.path.join(dst_dir, ".version")

    dll_path = os.path.join(dst_dir, "WinDivert64.dll")
    sys_path = os.path.join(dst_dir, "WinDivert64.sys")

    if os.path.exists(version_file):
        with open(version_file) as f:
            if f.read().strip() == version and os.path.exists(dll_path) and os.path.exists(sys_path):
                print(f"WinDivert {version} already present.")
                return

    url = f"https://github.com/basil00/WinDivert/releases/download/v{version}/WinDivert-{version}-A.zip"
    print(f"Downloading WinDivert {version} from {url}...")
    with urllib.request.urlopen(url) as response:
        with zipfile.ZipFile(io.BytesIO(response.read())) as z:
            with z.open(f"WinDivert-{version}-A/x64/WinDivert.dll") as src, open(dll_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            with z.open(f"WinDivert-{version}-A/x64/WinDivert64.sys") as src, open(sys_path, "wb") as dst:
                shutil.copyfileobj(src, dst)

    with open(version_file, "w") as f:
        f.write(version)
    print("Successfully fetched WinDivert binaries.")


def _linux_arch():
    if os.environ.get("PYDIVERT_TARGET_ARCH"):
        return os.environ["PYDIVERT_TARGET_ARCH"]
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    raise RuntimeError(f"Unsupported Linux architecture for eBPFDivert: {machine}")


def download_ebpfdivert(version):
    """Fetches libebpfdivert.so (self-contained: BPF object and libbpf linked in)."""
    dst_dir = os.path.join(ROOT, "pydivert", "bpf")
    version_file = os.path.join(dst_dir, ".version")
    dst_so = os.path.join(dst_dir, "libebpfdivert.so")
    os.makedirs(dst_dir, exist_ok=True)

    # Development: use a local build (e.g. ../ebpfdivert/libebpfdivert.so).
    local = os.environ.get("PYDIVERT_EBPFDIVERT_LOCAL")
    if local:
        shutil.copyfile(local, dst_so)
        with open(version_file, "w") as f:
            f.write(f"local:{os.path.abspath(local)}")
        print(f"Using local libebpfdivert from {local}")
        return

    arch = _linux_arch()
    stamp = f"{version}-{arch}"
    if os.path.exists(version_file):
        with open(version_file) as f:
            if f.read().strip() == stamp and os.path.exists(dst_so):
                print(f"eBPFDivert {stamp} already present.")
                return

    url = (
        f"https://github.com/ffalcinelli/ebpfdivert/releases/download/v{version}/"
        f"ebpfdivert-v{version}-linux-{arch}.tar.gz"
    )
    print(f"Downloading eBPFDivert {version} ({arch}) from {url}...")
    with urllib.request.urlopen(url) as response:
        data = response.read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        member = tar.getmember("./lib/libebpfdivert.so")
        src = tar.extractfile(member)
        if src is None:
            raise RuntimeError("libebpfdivert.so missing from the release archive")
        with src, open(dst_so, "wb") as dst:
            shutil.copyfileobj(src, dst)
    os.chmod(dst_so, 0o755)

    with open(version_file, "w") as f:
        f.write(stamp)
    print(f"Successfully fetched {dst_so}")


def _remove(path):
    """Keep other platforms' binaries out of a platform-specific wheel."""
    if os.path.exists(path):
        os.remove(path)
        version_file = os.path.join(os.path.dirname(path), ".version")
        if os.path.exists(version_file):
            os.remove(version_file)


def main():
    if os.environ.get("SKIP_FETCH_BINARIES") in ("1", "true", "TRUE"):
        print("Skipping fetching binaries as requested by SKIP_FETCH_BINARIES env var.")
        return
    try:
        win_ver, ebpf_ver = get_versions()
        # PYDIVERT_TARGET (set by hatch_build.py): "win_amd64", "linux", or
        # unset for a development checkout (the host platform's binaries).
        target = os.environ.get("PYDIVERT_TARGET")
        # Only platform wheel builds drop the other platform's binaries; a
        # development tree may be shared between the host and a VM.
        strip = target is not None
        if target is None:
            target = "win_amd64" if sys.platform == "win32" else "linux"
        if target == "win_amd64":
            download_windivert(win_ver)
            if strip:
                _remove(os.path.join(ROOT, "pydivert", "bpf", "libebpfdivert.so"))
        else:
            download_ebpfdivert(ebpf_ver)
            if strip:
                for name in ("WinDivert64.dll", "WinDivert64.sys"):
                    _remove(os.path.join(ROOT, "pydivert", "windivert_dll", name))
    except Exception as e:
        print(f"Error fetching binaries: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
