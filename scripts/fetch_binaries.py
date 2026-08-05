import io
import os
import re
import shutil
import sys
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

def download_ebpfdivert(version):
    """Downloads eBPF object file."""
    dst_dir = os.path.join(ROOT, "pydivert", "bpf")
    version_file = os.path.join(dst_dir, ".version")
    dst = os.path.join(dst_dir, "ebpfdivert.bpf.o")

    if os.path.exists(version_file):
        with open(version_file) as f:
            if f.read().strip() == version and os.path.exists(dst):
                print(f"eBPF driver {version} already present.")
                return

    url = f"https://github.com/ffalcinelli/ebpfdivert/releases/download/v{version}/ebpfdivert.bpf.o"
    print(f"Downloading eBPF driver {version} from {url}...")
    os.makedirs(dst_dir, exist_ok=True)
    with urllib.request.urlopen(url) as response, open(dst, "wb") as out_file:
        shutil.copyfileobj(response, out_file)

    with open(version_file, "w") as f:
        f.write(version)
    print(f"Successfully fetched eBPF driver: {dst}")

def main():
    try:
        win_ver, ebpf_ver = get_versions()
        download_windivert(win_ver)
        download_ebpfdivert(ebpf_ver)
    except Exception as e:
        print(f"Error fetching binaries: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
