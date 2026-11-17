#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
"""QEMU/KVM + cloud-init test VM manager for PyDivert (replaces Vagrant)."""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = Path(os.environ.get("DIVERT_VM_CACHE", Path.home() / ".cache" / "divert-vm"))
IMAGES_DIR = CACHE_DIR / "images"
RUNS_DIR = CACHE_DIR / "runs"
SSH_KEY = CACHE_DIR / "id_ed25519"

LINUX_IMAGE = "noble-server-cloudimg-amd64.img"
LINUX_URL = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
WINDOWS_IMAGE = Path(os.environ.get("DIVERT_WINDOWS_IMAGE", IMAGES_DIR / "windows-11.qcow2"))


def run_dir_for(target: str) -> Path:
    return RUNS_DIR / f"pydivert-{target}"


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def ensure_tools(need_win: bool = False) -> str:
    for tool in ("qemu-system-x86_64", "qemu-img", "ssh", "ssh-keygen"):
        if shutil.which(tool) is None:
            sys.exit(f"Missing required tool '{tool}'. Install QEMU and OpenSSH first.")
    if need_win and shutil.which("swtpm") is None:
        print("Warning: 'swtpm' not found; Windows 11 TPM 2.0 will be omitted.", file=sys.stderr)
    for iso_tool in ("genisoimage", "mkisofs", "xorrisofs", "cloud-localds"):
        if shutil.which(iso_tool) is not None:
            return iso_tool
    sys.exit("Missing ISO builder (install genisoimage, mkisofs, xorrisofs, or cloud-localds).")


def ensure_ssh_key() -> str:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not SSH_KEY.exists():
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(SSH_KEY)], check=True)
    return SSH_KEY.with_suffix(".pub").read_text().strip()


def ensure_linux_image() -> Path:
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    dest = IMAGES_DIR / LINUX_IMAGE
    if dest.exists():
        return dest
    part = dest.with_suffix(".img.part")
    print(f"Downloading {LINUX_URL} -> {dest} ...")
    try:
        with urllib.request.urlopen(LINUX_URL) as resp, open(part, "wb") as out:
            shutil.copyfileobj(resp, out, length=1024 * 1024)
        part.rename(dest)
    except Exception:
        part.unlink(missing_ok=True)
        raise
    return dest


def find_ovmf() -> tuple[Path, Path]:
    candidates = [
        (Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd"), Path("/usr/share/edk2/x64/OVMF_VARS.4m.fd")),
        (Path("/usr/share/edk2-ovmf/x64/OVMF_CODE.4m.fd"), Path("/usr/share/edk2-ovmf/x64/OVMF_VARS.4m.fd")),
        (Path("/usr/share/OVMF/OVMF_CODE_4M.fd"), Path("/usr/share/OVMF/OVMF_VARS_4M.fd")),
        (Path("/usr/share/OVMF/OVMF_CODE.fd"), Path("/usr/share/OVMF/OVMF_VARS.fd")),
    ]
    for code, vars_f in candidates:
        if code.exists() and vars_f.exists():
            return code, vars_f
    sys.exit("Missing OVMF firmware (install edk2-ovmf).")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def check_single_vm(active_target: str) -> None:
    if not RUNS_DIR.exists():
        return
    for entry in RUNS_DIR.iterdir():
        pid_file = entry / "qemu.pid"
        if not pid_file.exists():
            continue
        pid = int(pid_file.read_text().strip())
        if pid_alive(pid):
            if entry.name == f"pydivert-{active_target}":
                return
            sys.exit(
                f"Another VM is already running ({entry.name}, pid {pid}). "
                "Destroy it first to obey the one-VM-at-a-time policy."
            )


def build_seed_iso(rdir: Path, pubkey: str, iso_tool: str) -> Path:
    meta_data = rdir / "meta-data"
    user_data = rdir / "user-data"
    seed_iso = rdir / "seed.iso"
    meta_data.write_text("instance-id: pydivert-linux\nlocal-hostname: pydivert-linux\n")
    user_data.write_text(
        "#cloud-config\n"
        "users:\n"
        "  - name: divert\n"
        "    sudo: ALL=(ALL) NOPASSWD:ALL\n"
        "    shell: /bin/bash\n"
        "    lock_passwd: true\n"
        "    ssh_authorized_keys:\n"
        f"      - {pubkey}\n"
        "package_update: true\n"
        "packages:\n"
        "  - python3-pip\n"
        "  - python3-venv\n"
        "  - curl\n"
        "  - iproute2\n"
        "  - ethtool\n"
        "runcmd:\n"
        "  - curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/usr/local/bin sh\n"
        "  - mkdir -p /workspace\n"
        "  - mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600 workspace /workspace\n"
    )
    if iso_tool == "cloud-localds":
        subprocess.run(["cloud-localds", str(seed_iso), str(user_data), str(meta_data)], check=True)
    else:
        subprocess.run(
            [
                iso_tool,
                "-output",
                str(seed_iso),
                "-volid",
                "cidata",
                "-joliet",
                "-rock",
                str(user_data),
                str(meta_data),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return seed_iso


def ssh_base(port: int) -> list[str]:
    return [
        "ssh",
        "-i",
        str(SSH_KEY),
        "-p",
        str(port),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "divert@127.0.0.1",
    ]


def wait_for_ssh(port: int, pid: int, linux: bool, timeout: int = 360) -> None:
    deadline = time.monotonic() + timeout
    probe = "cloud-init status --wait >/dev/null 2>&1 || true; echo ready" if linux else "echo ready"
    while time.monotonic() < deadline:
        if not pid_alive(pid):
            sys.exit("QEMU exited unexpectedly while waiting for SSH. Check console.log.")
        res = subprocess.run([*ssh_base(port), probe], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if res.returncode == 0 and "ready" in res.stdout:
            return
        time.sleep(3)
    sys.exit(f"Timed out after {timeout}s waiting for VM SSH.")


def start_swtpm(rdir: Path) -> Path | None:
    if shutil.which("swtpm") is None:
        return None
    tpm_dir = rdir / "tpm"
    tpm_dir.mkdir(parents=True, exist_ok=True)
    sock = rdir / "swtpm.sock"
    pid_file = rdir / "swtpm.pid"
    subprocess.run(
        [
            "swtpm",
            "socket",
            "--tpmstate",
            f"dir={tpm_dir}",
            "--ctrl",
            f"type=unixio,path={sock}",
            "--tpm2",
            "--daemon",
            "--pid",
            f"file={pid_file}",
        ],
        check=True,
    )
    return sock


def add_kvm_flags(cmd: list[str]) -> None:
    if Path("/dev/kvm").exists() and os.access("/dev/kvm", os.R_OK | os.W_OK):
        cmd.extend(["-enable-kvm", "-cpu", "host"])
    else:
        print("Warning: /dev/kvm unavailable; running without KVM acceleration.", file=sys.stderr)
        cmd.extend(["-cpu", "max"])


def cmd_up(target: str) -> int:
    iso_tool = ensure_tools(need_win=(target == "windows"))
    check_single_vm(target)
    rdir = run_dir_for(target)
    pid_file = rdir / "qemu.pid"
    if pid_file.exists() and pid_alive(int(pid_file.read_text().strip())):
        port = int((rdir / "ssh.port").read_text().strip())
        print(f"{target} already running (ssh port {port})")
        return port

    shutil.rmtree(rdir, ignore_errors=True)
    rdir.mkdir(parents=True, exist_ok=True)
    ensure_ssh_key()
    port = free_port()
    (rdir / "ssh.port").write_text(str(port))

    if target == "linux":
        pubkey = SSH_KEY.with_suffix(".pub").read_text().strip()
        base_img = ensure_linux_image()
        overlay = rdir / "overlay.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base_img), str(overlay), "20G"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        seed_iso = build_seed_iso(rdir, pubkey, iso_tool)
        qemu_cmd = [
            "qemu-system-x86_64",
            "-name",
            "pydivert-linux",
            "-m",
            "2048",
            "-smp",
            "2",
            "-drive",
            f"file={overlay},if=virtio,format=qcow2",
            "-drive",
            f"file={seed_iso},media=cdrom,readonly=on",
            "-netdev",
            f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
            "-device",
            "virtio-net-pci,netdev=net0",
            "-virtfs",
            f"local,path={REPO_ROOT},mount_tag=workspace,security_model=mapped-xattr,id=workspace",
            "-nographic",
            "-daemonize",
            "-pidfile",
            str(pid_file),
            "-serial",
            f"file:{rdir / 'console.log'}",
        ]
        add_kvm_flags(qemu_cmd)
    else:
        if not WINDOWS_IMAGE.exists():
            sys.exit(
                f"Windows base image not found at {WINDOWS_IMAGE}. "
                "Create one with: python3 scripts/vm.py init-windows --iso /path/to/win11.iso"
            )
        ovmf_code, ovmf_vars = find_ovmf()
        vars_copy = rdir / "OVMF_VARS.fd"
        shutil.copy2(ovmf_vars, vars_copy)
        overlay = rdir / "overlay.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(WINDOWS_IMAGE), str(overlay)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        qemu_cmd = [
            "qemu-system-x86_64",
            "-name",
            "pydivert-windows",
            "-machine",
            "q35",
            "-m",
            "4096",
            "-smp",
            "2",
            "-drive",
            f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
            "-drive",
            f"if=pflash,format=raw,file={vars_copy}",
            "-drive",
            f"file={overlay},if=virtio,format=qcow2",
            "-netdev",
            f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
            "-device",
            "virtio-net-pci,netdev=net0",
            "-display",
            "none",
            "-daemonize",
            "-pidfile",
            str(pid_file),
        ]
        tpm_sock = start_swtpm(rdir)
        if tpm_sock is not None:
            qemu_cmd.extend(
                [
                    "-chardev",
                    f"socket,id=chrtpm,path={tpm_sock}",
                    "-tpmdev",
                    "emulator,id=tpm0,chardev=chrtpm",
                    "-device",
                    "tpm-tis,tpmdev=tpm0",
                ]
            )
        add_kvm_flags(qemu_cmd)

    subprocess.run(qemu_cmd, check=True)
    pid = int(pid_file.read_text().strip())
    print(f"Booting {target} (pid {pid}, ssh port {port})...")
    wait_for_ssh(port, pid, linux=(target == "linux"))
    return port


def get_port(target: str) -> int:
    rdir = run_dir_for(target)
    pid_file = rdir / "qemu.pid"
    if not pid_file.exists() or not pid_alive(int(pid_file.read_text().strip())):
        sys.exit(f"VM '{target}' is not running. Start it with: python3 scripts/vm.py up {target}")
    return int((rdir / "ssh.port").read_text().strip())


def sync_to_windows(port: int) -> None:
    excludes = ["--exclude=.git", "--exclude=.venv", "--exclude=.pytest_cache", "--exclude=__pycache__"]
    mkdir_ps = 'powershell -Command "New-Item -ItemType Directory -Force -Path C:\\pydivert | Out-Null"'
    subprocess.run([*ssh_base(port), mkdir_ps], check=True)
    tar_proc = subprocess.Popen(["tar", "-C", str(REPO_ROOT), *excludes, "-cf", "-", "."], stdout=subprocess.PIPE)
    ssh_proc = subprocess.run([*ssh_base(port), "tar -C C:/pydivert -xf -"], stdin=tar_proc.stdout, check=True)
    if tar_proc.wait() != 0 or ssh_proc.returncode != 0:
        sys.exit("Failed to sync repository to Windows VM.")


def cmd_exec(target: str, command: str) -> int:
    port = get_port(target)
    return subprocess.run([*ssh_base(port), command]).returncode


def cmd_ssh(target: str, args: list[str]) -> int:
    port = get_port(target)
    if args:
        return subprocess.run([*ssh_base(port), shlex.join(args)]).returncode
    return subprocess.run(ssh_base(port)).returncode


def cmd_destroy(target: str) -> None:
    rdir = run_dir_for(target)
    for pf in ("qemu.pid", "swtpm.pid"):
        pid_file = rdir / pf
        if pid_file.exists():
            pid = int(pid_file.read_text().strip())
            if pid_alive(pid):
                os.kill(pid, 15)
                for _ in range(20):
                    if not pid_alive(pid):
                        break
                    time.sleep(0.25)
                if pid_alive(pid):
                    os.kill(pid, 9)
    shutil.rmtree(rdir, ignore_errors=True)
    print(f"Destroyed {target}")


def cmd_run(target: str) -> int:
    try:
        port = cmd_up(target)
        if target == "linux":
            script = (
                "set -euo pipefail; "
                "rm -rf /tmp/work && cp -a /workspace /tmp/work; "
                "PYDIVERT_DIR=/tmp/work bash /tmp/work/scripts/run-tests-linux.sh; "
                "if [ -f /tmp/work/.coverage.linux ]; then cp /tmp/work/.coverage.linux /workspace/.coverage.linux; fi"
            )
            return cmd_exec("linux", f"bash -lc {shlex.quote(script)}")
        sync_to_windows(port)
        ps_prov = "powershell -ExecutionPolicy Bypass -File C:\\pydivert\\scripts\\provision-windows.ps1"
        rc = cmd_exec("windows", ps_prov)
        if rc != 0:
            return rc
        ps_test = "powershell -ExecutionPolicy Bypass -File C:\\pydivert\\scripts\\run-tests-windows.ps1"
        rc = cmd_exec("windows", ps_test)
        dl_cmd = (
            "if (Test-Path C:\\pydivert\\.coverage.windows) "
            "{ Get-Content -Raw -Encoding Byte C:\\pydivert\\.coverage.windows }"
        )
        cov_dl = subprocess.run([*ssh_base(port), dl_cmd], stdout=subprocess.PIPE)
        if cov_dl.returncode == 0 and cov_dl.stdout:
            (REPO_ROOT / ".coverage.windows").write_bytes(cov_dl.stdout)
        return rc
    finally:
        cmd_destroy(target)


def cmd_init_windows(iso_path: Path, virtio_iso: Path | None) -> None:
    iso_tool = ensure_tools(need_win=True)
    pubkey = ensure_ssh_key()
    if not iso_path.exists():
        sys.exit(f"Windows ISO not found: {iso_path}")
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    rdir = RUNS_DIR / "win-init"
    shutil.rmtree(rdir, ignore_errors=True)
    rdir.mkdir(parents=True, exist_ok=True)
    unattend_dir = rdir / "unattend"
    unattend_dir.mkdir()
    (unattend_dir / "setup.ps1").write_text(
        "$ErrorActionPreference = 'Continue'\n"
        "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0\n"
        "Start-Service sshd\n"
        "Set-Service -Name sshd -StartupType Automatic\n"
        "New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Enabled True "
        "-Direction Inbound -Protocol TCP -Action Allow -LocalPort 22\n"
        f"Set-Content -Path C:\\ProgramData\\ssh\\administrators_authorized_keys -Value '{pubkey}' -Encoding Ascii\n"
        "icacls C:\\ProgramData\\ssh\\administrators_authorized_keys "
        "/inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'\n"
        "shutdown /s /t 5\n"
    )
    pk = 'publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"'
    wcm_ns = 'xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"'
    (unattend_dir / "autounattend.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<unattend xmlns="urn:schemas-microsoft-com:unattend">\n'
        '  <settings pass="windowsPE">\n'
        f'    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" {pk}>\n'
        "      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>\n"
        "      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale>\n"
        "      <UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>\n"
        "    </component>\n"
        f'    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" {pk}>\n'
        "      <UserData><AcceptEula>true</AcceptEula></UserData>\n"
        "    </component>\n"
        "  </settings>\n"
        '  <settings pass="oobeSystem">\n'
        f'    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" {pk}>\n'
        "      <OOBE><HideEULAPage>true</HideEULAPage>"
        "<SkipMachineOOBE>true</SkipMachineOOBE><SkipUserOOBE>true</SkipUserOOBE></OOBE>\n"
        "      <UserAccounts><LocalAccounts>"
        f'<LocalAccount wcm:action="add" {wcm_ns}>\n'
        "        <Name>divert</Name><Group>Administrators</Group>\n"
        "        <Password><Value>divert</Value><PlainText>true</PlainText></Password>\n"
        "      </LocalAccount></LocalAccounts></UserAccounts>\n"
        "      <AutoLogon><Enabled>true</Enabled><Username>divert</Username>"
        "<Password><Value>divert</Value><PlainText>true</PlainText></Password>"
        "<LogonCount>1</LogonCount></AutoLogon>\n"
        f'      <FirstLogonCommands><SynchronousCommand wcm:action="add" {wcm_ns}>\n'
        "        <Order>1</Order>"
        "<CommandLine>powershell -ExecutionPolicy Bypass -File E:\\setup.ps1</CommandLine>\n"
        "      </SynchronousCommand></FirstLogonCommands>\n"
        "    </component>\n"
        "  </settings>\n"
        "</unattend>\n"
    )
    seed_iso = rdir / "autounattend.iso"
    subprocess.run([iso_tool, "-output", str(seed_iso), "-joliet", "-rock", str(unattend_dir)], check=True)
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(WINDOWS_IMAGE), "60G"], check=True)
    ovmf_code, ovmf_vars = find_ovmf()
    vars_copy = rdir / "OVMF_VARS.fd"
    shutil.copy2(ovmf_vars, vars_copy)
    cmd = [
        "qemu-system-x86_64",
        "-machine",
        "q35",
        "-m",
        "4096",
        "-smp",
        "4",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
        "-drive",
        f"if=pflash,format=raw,file={vars_copy}",
        "-drive",
        f"file={WINDOWS_IMAGE},if=ide,format=qcow2",
        "-drive",
        f"file={iso_path},media=cdrom,index=1",
        "-drive",
        f"file={seed_iso},media=cdrom,index=2",
    ]
    if virtio_iso is not None:
        cmd.extend(["-drive", f"file={virtio_iso},media=cdrom,index=3"])
    tpm_sock = start_swtpm(rdir)
    if tpm_sock is not None:
        cmd.extend(
            [
                "-chardev",
                f"socket,id=chrtpm,path={tpm_sock}",
                "-tpmdev",
                "emulator,id=tpm0,chardev=chrtpm",
                "-device",
                "tpm-tis,tpmdev=tpm0",
            ]
        )
    add_kvm_flags(cmd)
    print("Installing Windows 11 base image (this shuts down automatically once OpenSSH is configured)...")
    subprocess.run(cmd, check=True)
    shutil.rmtree(rdir, ignore_errors=True)


def cmd_status() -> None:
    for target in ("linux", "windows"):
        rdir = run_dir_for(target)
        pid_file = rdir / "qemu.pid"
        if pid_file.exists():
            pid = int(pid_file.read_text().strip())
            if pid_alive(pid):
                port = (rdir / "ssh.port").read_text().strip()
                print(f"{target}: running (pid {pid}, ssh port {port})")
                continue
        print(f"{target}: stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage QEMU/KVM test VMs for PyDivert")
    sub = parser.add_subparsers(dest="cmd", required=True)

    for name in ("up", "destroy", "run"):
        p = sub.add_parser(name)
        p.add_argument("target", choices=("linux", "windows"), default="linux", nargs="?")

    p_exec = sub.add_parser("exec")
    p_exec.add_argument("target", choices=("linux", "windows"))
    p_exec.add_argument("command")

    p_ssh = sub.add_parser("ssh")
    p_ssh.add_argument("target", choices=("linux", "windows"), default="linux", nargs="?")
    p_ssh.add_argument("args", nargs=argparse.REMAINDER)

    p_init = sub.add_parser("init-windows")
    p_init.add_argument("--iso", type=Path, required=True, help="Path to Windows 11 installation ISO")
    p_init.add_argument("--virtio-iso", type=Path, default=None, help="Optional virtio-win ISO")

    sub.add_parser("status")

    args = parser.parse_args()
    if args.cmd == "up":
        cmd_up(args.target)
    elif args.cmd == "destroy":
        cmd_destroy(args.target)
    elif args.cmd == "exec":
        sys.exit(cmd_exec(args.target, args.command))
    elif args.cmd == "ssh":
        sys.exit(cmd_ssh(args.target, args.args))
    elif args.cmd == "run":
        sys.exit(cmd_run(args.target))
    elif args.cmd == "init-windows":
        cmd_init_windows(args.iso, args.virtio_iso)
    elif args.cmd == "status":
        cmd_status()


if __name__ == "__main__":
    main()
