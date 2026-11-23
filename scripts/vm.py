#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
"""QEMU/KVM test VM manager (replaces Vagrant).

Linux runs on an Ubuntu 24.04 cloud image provisioned by cloud-init, with the repository mounted over 9p.
Windows runs on a Windows 11 base image built once from an installation ISO by ``init-windows`` (shared by
pydivert, jdivert and avulse under ``~/.cache/divert-vm/images``). Each ``run`` boots a throw-away overlay,
runs the suite and destroys the VM. Only one VM runs at a time across all the repositories.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# --- Project configuration. The rest of the file is shared by pydivert, jdivert and avulse except cmd_run. ---
PROJECT = "pydivert"
UBUNTU = "https://cloud-images.ubuntu.com"
LINUX_TARGETS = {
    "linux": {"image": f"{UBUNTU}/noble/current/noble-server-cloudimg-amd64.img", "memory_mb": 2048, "cpus": 2},
}
LINUX_PACKAGES = ["python3-pip", "python3-venv", "curl", "iproute2", "ethtool"]
LINUX_RUNCMD = ["curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/usr/local/bin sh"]
WINDOWS_DIR = "C:\\pydivert"
WINDOWS_MEMORY_MB = 4096
WINDOWS_CPUS = 2
SYNC_EXCLUDES = [".git", ".venv", ".pytest_cache", "__pycache__"]
# --------------------------------------------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = Path(os.environ.get("DIVERT_VM_CACHE", Path.home() / ".cache" / "divert-vm"))
IMAGES_DIR = CACHE_DIR / "images"
RUNS_DIR = CACHE_DIR / "runs"
SSH_KEY = CACHE_DIR / "id_ed25519"

WINDOWS_IMAGE = Path(os.environ.get("DIVERT_WINDOWS_IMAGE", IMAGES_DIR / "windows-11.qcow2"))
WINDOWS_VARS = WINDOWS_IMAGE.with_name(WINDOWS_IMAGE.name + ".vars.fd")
TARGETS = (*LINUX_TARGETS, "windows")


def run_dir_for(target: str) -> Path:
    return RUNS_DIR / f"{PROJECT}-{target}"


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def read_pid(pid_file: Path) -> int | None:
    try:
        return int(pid_file.read_text().strip())
    except (OSError, ValueError):
        return None


def ensure_tools() -> str:
    for tool in ("qemu-system-x86_64", "qemu-img", "ssh", "scp", "ssh-keygen"):
        if shutil.which(tool) is None:
            sys.exit(f"Missing required tool '{tool}'. Install QEMU and OpenSSH first.")
    for iso_tool in ("genisoimage", "mkisofs", "xorrisofs"):
        if shutil.which(iso_tool) is not None:
            return iso_tool
    sys.exit("Missing ISO builder (install genisoimage, mkisofs, or xorrisofs).")


def ensure_ssh_key() -> str:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not SSH_KEY.exists():
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(SSH_KEY)], check=True)
    return SSH_KEY.with_suffix(".pub").read_text().strip()


def ensure_linux_image(target: str) -> Path:
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    url = str(LINUX_TARGETS[target]["image"])
    dest = IMAGES_DIR / url.rsplit("/", 1)[1]
    if dest.exists():
        return dest
    part = dest.with_name(dest.name + ".part")
    print(f"Downloading {url} -> {dest} ...")
    try:
        with urllib.request.urlopen(url) as resp, open(part, "wb") as out:
            shutil.copyfileobj(resp, out, length=1024 * 1024)
        part.rename(dest)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    return dest


def find_ovmf() -> tuple[Path, Path]:
    # The non-Secure-Boot firmware: test-signed drivers (avulse) need Secure Boot off.
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


def check_single_vm(active: str) -> None:
    """Refuse to start a VM while another one (from any of the repositories) is running."""
    if not RUNS_DIR.exists():
        return
    for entry in RUNS_DIR.iterdir():
        pid = read_pid(entry / "qemu.pid")
        if pid is None or not pid_alive(pid) or entry.name == active:
            continue
        sys.exit(
            f"Another VM is already running ({entry.name}, pid {pid}). "
            "Destroy it first to obey the one-VM-at-a-time policy."
        )


def add_kvm_flags(cmd: list[str], windows: bool = False) -> None:
    if Path("/dev/kvm").exists() and os.access("/dev/kvm", os.R_OK | os.W_OK):
        cpu = "host,hv_relaxed,hv_vapic,hv_spinlocks=0x1fff,hv_time" if windows else "host"
        cmd.extend(["-enable-kvm", "-cpu", cpu])
    else:
        print("Warning: /dev/kvm unavailable; running without KVM acceleration.", file=sys.stderr)
        cmd.extend(["-cpu", "max"])


def ssh_opts() -> list[str]:
    return [
        "-i",
        str(SSH_KEY),
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
        "-o",
        "ServerAliveInterval=30",
    ]


def ssh_base(port: int) -> list[str]:
    return ["ssh", *ssh_opts(), "-p", str(port), "divert@127.0.0.1"]


def scp_from(port: int, remote: str, local: Path) -> int:
    return subprocess.run(["scp", *ssh_opts(), "-P", str(port), f"divert@127.0.0.1:{remote}", str(local)]).returncode


def monitor_cmd(sock_path: Path, command: str) -> None:
    """Send one command to a QEMU human monitor listening on a unix socket (best effort)."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect(str(sock_path))
            s.recv(4096)
            s.sendall(command.encode() + b"\n")
            time.sleep(0.2)
            s.recv(4096)
    except OSError:
        pass


# --- Linux ---------------------------------------------------------------------------------------------------


def build_seed_iso(rdir: Path, target: str, pubkey: str, iso_tool: str) -> Path:
    meta_data = rdir / "meta-data"
    user_data = rdir / "user-data"
    seed_iso = rdir / "seed.iso"
    meta_data.write_text(f"instance-id: {PROJECT}-{target}\nlocal-hostname: {PROJECT}-{target}\n")
    # JSON strings are valid YAML scalars, multi-line runcmd scripts included.
    packages = "".join(f"  - {json.dumps(p)}\n" for p in LINUX_PACKAGES)
    runcmd = "".join(f"  - {json.dumps(c)}\n" for c in LINUX_RUNCMD)
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
        f"packages:\n{packages}"
        f"runcmd:\n{runcmd}"
        "  - mkdir -p /workspace\n"
        "  - mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600 workspace /workspace\n"
    )
    subprocess.run(
        [iso_tool, "-output", str(seed_iso), "-volid", "cidata", "-joliet", "-rock", str(user_data), str(meta_data)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return seed_iso


def linux_qemu_cmd(rdir: Path, target: str, port: int, iso_tool: str) -> list[str]:
    spec = LINUX_TARGETS[target]
    pubkey = ensure_ssh_key()
    base = ensure_linux_image(target)
    overlay = rdir / "overlay.qcow2"
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(overlay), "20G"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    seed_iso = build_seed_iso(rdir, target, pubkey, iso_tool)
    cmd = [
        "qemu-system-x86_64",
        "-name",
        f"{PROJECT}-{target}",
        "-m",
        str(spec["memory_mb"]),
        "-smp",
        str(spec["cpus"]),
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
        "-display",
        "none",
        "-serial",
        f"file:{rdir / 'console.log'}",
    ]
    add_kvm_flags(cmd)
    return cmd


# --- Windows -------------------------------------------------------------------------------------------------
#
# Windows only has inbox drivers for emulated hardware, so the base image is installed and run on the same
# devices: the q35 AHCI controller (SATA disk) and an e1000e NIC. No TPM (LabConfig bypasses the check, and a
# fresh TPM per run would trip BitLocker) and no Secure Boot (test signing needs it off).


def windows_machine_args(name: str, vars_fd: Path, disk: Path) -> list[str]:
    ovmf_code, _ = find_ovmf()
    return [
        "qemu-system-x86_64",
        "-name",
        name,
        "-machine",
        "q35",
        "-rtc",
        "base=localtime",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
        "-drive",
        f"if=pflash,format=raw,file={vars_fd}",
        "-drive",
        f"id=disk0,if=none,format=qcow2,file={disk}",
        "-device",
        "ide-hd,drive=disk0,bus=ide.0,bootindex=0",
        "-display",
        "none",
    ]


def windows_qemu_cmd(rdir: Path, port: int) -> list[str]:
    if not WINDOWS_IMAGE.exists():
        sys.exit(
            f"Windows base image not found at {WINDOWS_IMAGE}. Create one with: "
            "python3 scripts/vm.py init-windows --iso /path/to/win11.iso [--lang it-IT]"
        )
    vars_copy = rdir / "OVMF_VARS.fd"
    shutil.copy2(WINDOWS_VARS if WINDOWS_VARS.exists() else find_ovmf()[1], vars_copy)
    overlay = rdir / "overlay.qcow2"
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(WINDOWS_IMAGE), str(overlay)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    cmd = windows_machine_args(f"{PROJECT}-windows", vars_copy, overlay)
    cmd += [
        "-m",
        str(WINDOWS_MEMORY_MB),
        "-smp",
        str(WINDOWS_CPUS),
        "-netdev",
        f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
        "-device",
        "e1000e,netdev=net0",
        "-monitor",
        f"unix:{rdir / 'monitor.sock'},server,nowait",
    ]
    add_kvm_flags(cmd, windows=True)
    return cmd


def unattend_xml(lang: str) -> str:
    comp = 'processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"'
    bypass = "".join(
        f'<RunSynchronousCommand wcm:action="add"><Order>{i}</Order>'
        f"<Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v {key} /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>"
        for i, key in enumerate(("BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck", "BypassCPUCheck"), 1)
    )
    partition = '<CreatePartition wcm:action="add"><Order>{0}</Order><Type>{1}</Type>{2}</CreatePartition>'
    modify = '<ModifyPartition wcm:action="add"><Order>{0}</Order><PartitionID>{0}</PartitionID>{1}</ModifyPartition>'
    partitions = (
        partition.format(1, "EFI", "<Size>260</Size>")
        + partition.format(2, "MSR", "<Size>16</Size>")
        + partition.format(3, "Primary", "<Extend>true</Extend>")
    )
    modifies = (
        modify.format(1, "<Format>FAT32</Format><Label>System</Label>")
        + modify.format(2, "")
        + modify.format(3, "<Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter>")
    )
    dword = "/t REG_DWORD /d 1 /f"
    password = "<Password><Value>divert</Value><PlainText>true</PlainText></Password>"
    # FirstLogonCommands: the unattend ISO's drive letter is not fixed, look for setup.ps1 on each drive.
    first_logon = (
        "cmd /c for %d in (D E F G H I) do if exist %d:\\divert-setup.ps1 "
        "powershell -NoProfile -ExecutionPolicy Bypass -File %d:\\divert-setup.ps1"
    )
    return f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" {comp}>
      <SetupUILanguage><UILanguage>{lang}</UILanguage></SetupUILanguage>
      <InputLocale>{lang}</InputLocale><SystemLocale>{lang}</SystemLocale>
      <UILanguage>{lang}</UILanguage><UserLocale>{lang}</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" {comp}>
      <RunSynchronous>{bypass}</RunSynchronous>
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>{partitions}</CreatePartitions>
          <ModifyPartitions>{modifies}</ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall><OSImage><InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo></OSImage></ImageInstall>
      <UserData>
        <AcceptEula>true</AcceptEula>
        <!-- Generic Windows 11 Pro key: selects the edition, does not activate it. -->
        <ProductKey><Key>VK7JG-NPHTM-C97JM-9MPGT-3V66T</Key><WillShowUI>OnError</WillShowUI></ProductKey>
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" {comp}>
      <ComputerName>divert-win</ComputerName>
    </component>
    <component name="Microsoft-Windows-Deployment" {comp}>
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add"><Order>1</Order>
          <Path>reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OOBE /v BypassNRO {dword}</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add"><Order>2</Order>
          <Path>reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\BitLocker /v PreventDeviceEncryption {dword}</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" {comp}>
      <InputLocale>{lang}</InputLocale><SystemLocale>{lang}</SystemLocale>
      <UILanguage>{lang}</UILanguage><UserLocale>{lang}</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" {comp}>
      <OOBE>
        <HideEULAPage>true</HideEULAPage><HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts><LocalAccounts><LocalAccount wcm:action="add">
        <Name>divert</Name><Group>Administrators</Group>{password}
      </LocalAccount></LocalAccounts></UserAccounts>
      <AutoLogon><Enabled>true</Enabled><Username>divert</Username>{password}<LogonCount>1</LogonCount></AutoLogon>
      <FirstLogonCommands><SynchronousCommand wcm:action="add">
        <Order>1</Order><CommandLine>{first_logon}</CommandLine>
      </SynchronousCommand></FirstLogonCommands>
    </component>
  </settings>
</unattend>
"""


def setup_ps1(pubkey: str) -> str:
    return f"""$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
Start-Transcript -Path C:\\divert-setup.log
Set-LocalUser -Name divert -PasswordNeverExpires $true
powercfg /hibernate off
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
# Elevated tokens for the local admin over the network, no automatic updates or reboots during test runs.
$policies = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
Set-ItemProperty -Path $policies -Name LocalAccountTokenFilterPolicy -Type DWord -Value 1
$au = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU'
New-Item -Path $au -Force | Out-Null
Set-ItemProperty -Path $au -Name NoAutoUpdate -Type DWord -Value 1
Set-ItemProperty -Path $au -Name NoAutoRebootWithLoggedOnUsers -Type DWord -Value 1

for ($i = 1; $i -le 60; $i++) {{
    try {{ Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 https://api.github.com | Out-Null; break }}
    catch {{ Start-Sleep 5 }}
}}

# The Win32-OpenSSH MSI is quick and works on every build; the OpenSSH.Server capability comes from Windows
# Update and can hang for a long time on a fresh install, so it is only the fallback.
Write-Host 'Installing Win32-OpenSSH from GitHub'
for ($i = 1; $i -le 10; $i++) {{
    try {{
        $rel = Invoke-RestMethod -UseBasicParsing https://api.github.com/repos/PowerShell/Win32-OpenSSH/releases/latest
        $asset = $rel.assets | Where-Object name -like 'OpenSSH-Win64-v*.msi' | Select-Object -First 1
        Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile C:\\openssh.msi
        break
    }} catch {{ Write-Warning "Download failed (attempt $i): $($_.Exception.Message)"; Start-Sleep 10 }}
}}
if (Test-Path C:\\openssh.msi) {{
    Start-Process msiexec.exe -Wait -ArgumentList '/i C:\\openssh.msi /qn'
    Remove-Item C:\\openssh.msi -ErrorAction SilentlyContinue
}}
if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {{
    Write-Host 'Falling back to the OpenSSH.Server capability (at most 30 minutes)'
    $job = Start-Job {{
        Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | Add-WindowsCapability -Online
    }}
    Wait-Job $job -Timeout 1800 | Out-Null
}}
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
New-NetFirewallRule -Name divert-sshd -DisplayName 'OpenSSH Server (divert)' -Enabled True -Profile Any `
    -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
$keys = 'C:\\ProgramData\\ssh\\administrators_authorized_keys'
Set-Content -Path $keys -Value '{pubkey}' -Encoding Ascii
icacls $keys /inheritance:r /grant '*S-1-5-32-544:F' /grant 'SYSTEM:F'
Stop-Transcript
# Report the result on COM1: init-windows only keeps the image when sshd is running.
$sshd = Get-Service sshd -ErrorAction SilentlyContinue
$com = New-Object System.IO.Ports.SerialPort COM1, 115200
$com.Open()
$com.WriteLine("divert-setup: sshd=$(if ($sshd) {{ $sshd.Status }} else {{ 'missing' }})")
$com.Close()
shutdown /s /t 10 /f
"""


def run_installer(cmd: list[str], rdir: Path, monitor: Path, timeout_h: float) -> None:
    """Run the installer VM in the foreground until Windows powers it off, taking periodic screenshots."""
    shot = rdir / "screen.png"
    proc = subprocess.Popen(cmd)
    (rdir / "qemu.pid").write_text(str(proc.pid))
    start = last_shot = time.monotonic()
    try:
        while proc.poll() is None:
            elapsed = time.monotonic() - start
            if elapsed < 20:
                # Answer the ISO's "Press any key to boot from CD or DVD" prompt, only while it can be up:
                # later, Enter would press Setup's focused Cancel button.
                monitor_cmd(monitor, "sendkey ret")
            if time.monotonic() - last_shot > 120:
                monitor_cmd(monitor, f"screendump {shot} -f png")
                last_shot = time.monotonic()
            if elapsed > timeout_h * 3600:
                monitor_cmd(monitor, f"screendump {shot} -f png")
                sys.exit(f"Windows installation timed out; see {shot}.")
            time.sleep(1)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    # QEMU also exits with 0 when killed by a signal: only the setup script's report counts as success.
    report = (rdir / "serial.log").read_text(errors="replace") if (rdir / "serial.log").exists() else ""
    if "divert-setup: sshd=Running" not in report:
        sys.exit(
            f"The Windows installation did not finish (QEMU exit code {proc.returncode}, "
            f"setup report: {report.strip()!r}); see {shot} and C:\\divert-setup.log in the image."
        )


def cmd_init_windows(iso_path: Path, lang: str, timeout_h: float) -> None:
    """Install the Windows 11 base image unattended, then check that it boots and answers SSH."""
    iso_tool = ensure_tools()
    pubkey = ensure_ssh_key()
    if not iso_path.exists():
        sys.exit(f"Windows ISO not found: {iso_path}")
    if WINDOWS_IMAGE.exists():
        sys.exit(f"{WINDOWS_IMAGE} already exists; delete it (and {WINDOWS_VARS.name}) to rebuild it.")
    check_single_vm("win-init")
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    rdir = RUNS_DIR / "win-init"
    shutil.rmtree(rdir, ignore_errors=True)
    unattend_dir = rdir / "unattend"
    unattend_dir.mkdir(parents=True)
    (unattend_dir / "autounattend.xml").write_text(unattend_xml(lang))
    (unattend_dir / "divert-setup.ps1").write_text(setup_ps1(pubkey))
    seed_iso = rdir / "unattend.iso"
    subprocess.run(
        [iso_tool, "-output", str(seed_iso), "-volid", "UNATTEND", "-joliet", "-rock", str(unattend_dir)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    part = WINDOWS_IMAGE.with_name(WINDOWS_IMAGE.name + ".part")
    part.unlink(missing_ok=True)
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(part), "64G"], check=True, stdout=subprocess.DEVNULL)
    vars_copy = rdir / "OVMF_VARS.fd"
    shutil.copy2(find_ovmf()[1], vars_copy)
    monitor = rdir / "monitor.sock"
    cmd = windows_machine_args("divert-win-init", vars_copy, part)
    cmd += [
        "-m",
        "4096",
        "-smp",
        "4",
        "-drive",
        f"id=cd0,if=none,media=cdrom,readonly=on,file={iso_path}",
        "-device",
        "ide-cd,drive=cd0,bus=ide.1,bootindex=1",
        "-drive",
        f"id=cd1,if=none,media=cdrom,readonly=on,file={seed_iso}",
        "-device",
        "ide-cd,drive=cd1,bus=ide.2",
        "-netdev",
        "user,id=net0",
        "-device",
        "e1000e,netdev=net0",
        "-monitor",
        f"unix:{monitor},server,nowait",
        "-serial",
        f"file:{rdir / 'serial.log'}",
    ]
    add_kvm_flags(cmd, windows=True)
    print(f"Installing Windows into {part} (progress screenshots in {rdir / 'screen.png'}) ...")
    run_installer(cmd, rdir, monitor, timeout_h)
    shutil.copy2(vars_copy, WINDOWS_VARS)
    part.rename(WINDOWS_IMAGE)
    print(f"Installed {WINDOWS_IMAGE}; checking that it boots and answers SSH ...")
    try:
        port = cmd_up("windows")
        subprocess.run([*ssh_base(port), "ver"], check=True)
    except BaseException:
        WINDOWS_IMAGE.rename(part)
        print(f"The new image does not answer SSH; kept it as {part} for inspection.", file=sys.stderr)
        raise
    finally:
        cmd_destroy("windows")
    shutil.rmtree(rdir, ignore_errors=True)
    print(f"Windows base image ready: {WINDOWS_IMAGE}")


# --- VM lifecycle --------------------------------------------------------------------------------------------


def ssh_probe(port: int, linux: bool) -> str:
    probe = (
        "cloud-init status --wait >/dev/null 2>&1; mountpoint -q /workspace && echo ready || echo nomount"
        if linux
        else "echo ready"
    )
    res = subprocess.run([*ssh_base(port), probe], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return res.stdout if res.returncode == 0 else ""


def wait_for_ssh(port: int, pid: int, linux: bool, timeout: int = 900) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not pid_alive(pid):
            sys.exit("QEMU exited unexpectedly while waiting for SSH.")
        out = ssh_probe(port, linux)
        if "nomount" in out:
            sys.exit("cloud-init finished but /workspace is not mounted (9p); see console.log in the run dir.")
        if "ready" in out:
            return
        time.sleep(3)
    sys.exit(f"Timed out after {timeout}s waiting for VM SSH.")


def wait_for_ssh_down(port: int, timeout: int = 300) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not ssh_probe(port, linux=False):
            return
        time.sleep(2)
    sys.exit("The VM did not go down for the reboot.")


def cmd_up(target: str) -> int:
    iso_tool = ensure_tools()
    rdir = run_dir_for(target)
    check_single_vm(rdir.name)
    pid_file = rdir / "qemu.pid"
    pid = read_pid(pid_file)
    if pid is not None and pid_alive(pid):
        port = int((rdir / "ssh.port").read_text().strip())
        print(f"{target} already running (ssh port {port})")
        return port

    shutil.rmtree(rdir, ignore_errors=True)
    rdir.mkdir(parents=True, exist_ok=True)
    ensure_ssh_key()
    port = free_port()
    (rdir / "ssh.port").write_text(str(port))
    if target in LINUX_TARGETS:
        qemu_cmd = linux_qemu_cmd(rdir, target, port, iso_tool)
    else:
        qemu_cmd = windows_qemu_cmd(rdir, port)
    qemu_cmd += ["-daemonize", "-pidfile", str(pid_file)]
    subprocess.run(qemu_cmd, check=True)
    pid = read_pid(pid_file)
    assert pid is not None
    print(f"Booting {target} (pid {pid}, ssh port {port})...")
    wait_for_ssh(port, pid, linux=(target in LINUX_TARGETS))
    return port


def get_port(target: str) -> int:
    rdir = run_dir_for(target)
    pid = read_pid(rdir / "qemu.pid")
    if pid is None or not pid_alive(pid):
        sys.exit(f"VM '{target}' is not running. Start it with: python3 scripts/vm.py up {target}")
    return int((rdir / "ssh.port").read_text().strip())


def cmd_exec(target: str, command: str) -> int:
    return subprocess.run([*ssh_base(get_port(target)), command]).returncode


def cmd_ssh(target: str, args: list[str]) -> int:
    port = get_port(target)
    if args:
        return subprocess.run([*ssh_base(port), shlex.join(args)]).returncode
    return subprocess.run(ssh_base(port)).returncode


def cmd_reboot(target: str) -> None:
    port = get_port(target)
    pid = read_pid(run_dir_for(target) / "qemu.pid")
    assert pid is not None
    subprocess.run([*ssh_base(port), "shutdown /r /t 0" if target == "windows" else "sudo systemctl reboot"])
    wait_for_ssh_down(port)
    wait_for_ssh(port, pid, linux=(target in LINUX_TARGETS))


def cmd_destroy(target: str) -> None:
    rdir = run_dir_for(target)
    pid = read_pid(rdir / "qemu.pid")
    if pid is not None and pid_alive(pid):
        os.kill(pid, 15)
        for _ in range(40):
            if not pid_alive(pid):
                break
            time.sleep(0.25)
        if pid_alive(pid):
            os.kill(pid, 9)
    shutil.rmtree(rdir, ignore_errors=True)
    print(f"Destroyed {target}")


def sync_to_windows(port: int) -> None:
    excludes = [f"--exclude={e}" for e in SYNC_EXCLUDES]
    subprocess.run([*ssh_base(port), f"if not exist {WINDOWS_DIR} mkdir {WINDOWS_DIR}"], check=True)
    tar_proc = subprocess.Popen(["tar", "-C", str(REPO_ROOT), *excludes, "-cf", "-", "."], stdout=subprocess.PIPE)
    ssh_rc = subprocess.run([*ssh_base(port), f"tar -C {WINDOWS_DIR} -xf -"], stdin=tar_proc.stdout).returncode
    if tar_proc.stdout is not None:
        tar_proc.stdout.close()
    if tar_proc.wait() != 0 or ssh_rc != 0:
        sys.exit("Failed to sync the repository to the Windows VM.")


def cmd_status() -> None:
    for target in TARGETS:
        rdir = run_dir_for(target)
        pid = read_pid(rdir / "qemu.pid")
        if pid is not None and pid_alive(pid):
            port = (rdir / "ssh.port").read_text().strip()
            print(f"{target}: running (pid {pid}, ssh port {port})")
        else:
            print(f"{target}: stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description=f"Manage QEMU/KVM test VMs for {PROJECT}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    for name in ("up", "destroy", "reboot", "run"):
        p = sub.add_parser(name)
        p.add_argument("target", choices=TARGETS, default=TARGETS[0], nargs="?")
    p.add_argument("args", nargs=argparse.REMAINDER, help="extra arguments for the test command")

    p_exec = sub.add_parser("exec")
    p_exec.add_argument("target", choices=TARGETS)
    p_exec.add_argument("command")

    p_ssh = sub.add_parser("ssh")
    p_ssh.add_argument("target", choices=TARGETS, default=TARGETS[0], nargs="?")
    p_ssh.add_argument("args", nargs=argparse.REMAINDER)

    p_init = sub.add_parser("init-windows", help="build the shared Windows 11 base image from an ISO")
    p_init.add_argument("--iso", type=Path, required=True, help="Windows 11 installation ISO")
    p_init.add_argument("--lang", default="en-US", help="the ISO's language, e.g. it-IT (default en-US)")
    p_init.add_argument("--timeout-hours", type=float, default=3.0)

    sub.add_parser("status")

    args = parser.parse_args()
    if args.cmd == "up":
        cmd_up(args.target)
    elif args.cmd == "destroy":
        cmd_destroy(args.target)
    elif args.cmd == "reboot":
        cmd_reboot(args.target)
    elif args.cmd == "exec":
        sys.exit(cmd_exec(args.target, args.command))
    elif args.cmd == "ssh":
        sys.exit(cmd_ssh(args.target, args.args))
    elif args.cmd == "run":
        sys.exit(cmd_run(args.target, args.args))
    elif args.cmd == "init-windows":
        cmd_init_windows(args.iso.expanduser(), args.lang, args.timeout_hours)
    elif args.cmd == "status":
        cmd_status()


# --- Project test runs ----------------------------------------------------------------------------------------


def cmd_run(target: str, extra: list[str]) -> int:
    if extra:
        sys.exit("pydivert's run takes no extra arguments.")
    try:
        port = cmd_up(target)
        if target in LINUX_TARGETS:
            script = (
                "set -euo pipefail; "
                "rm -rf /tmp/work && cp -a /workspace /tmp/work; "
                "rc=0; sudo -E env PYDIVERT_DIR=/tmp/work bash /tmp/work/scripts/run-tests-linux.sh || rc=$?; "
                "if [ -f /tmp/work/.coverage.linux ]; then cp /tmp/work/.coverage.linux /workspace/; fi; "
                "exit $rc"
            )
            return cmd_exec(target, f"bash -c {shlex.quote(script)}")
        sync_to_windows(port)
        ps = "powershell -NoProfile -ExecutionPolicy Bypass -File"
        rc = cmd_exec("windows", f"{ps} {WINDOWS_DIR}\\scripts\\provision-windows.ps1")
        if rc != 0:
            return rc
        rc = cmd_exec("windows", f"{ps} {WINDOWS_DIR}\\scripts\\run-tests-windows.ps1")
        cov = REPO_ROOT / ".coverage.windows"
        if scp_from(port, "C:/pydivert/.coverage.windows", cov) != 0:
            print("Warning: could not copy .coverage.windows back from the VM.", file=sys.stderr)
        return rc
    finally:
        cmd_destroy(target)


if __name__ == "__main__":
    main()
