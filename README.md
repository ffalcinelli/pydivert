# PyDivert v4.0.0 🚀

[![github-actions](https://github.com/ffalcinelli/pydivert/actions/workflows/ci.yml/badge.svg)](https://github.com/ffalcinelli/pydivert/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/github/ffalcinelli/pydivert/main.svg)](https://codecov.io/gh/ffalcinelli/pydivert)
[![latest_release](https://img.shields.io/pypi/v/pydivert.svg)](https://pypi.python.org/pypi/pydivert)
[![docs](https://img.shields.io/badge/docs-pdoc-blue.svg)](https://ffalcinelli.github.io/pydivert/)
[![python_versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://pypi.python.org/pypi/pydivert)
[![license](https://img.shields.io/pypi/l/pydivert.svg)](https://github.com/ffalcinelli/pydivert/blob/main/LICENSE)
[![Snyk](https://snyk.io/test/github/ffalcinelli/pydivert/badge.svg)](https://snyk.io/test/github/ffalcinelli/pydivert)

**PyDivert** is a powerful network packet capture and injection library for Python. While it started as a binding for [WinDivert](https://reqrypt.org/windivert.html), **version 4.0.0** introduces a unified, cross-platform abstraction layer that allows you to write network tools once and run them on **Windows, Linux, and BSD**.

---

## 🌟 Key Features in v4.0.0

- **Unified Cross-Platform API**: Use the `PyDivert` class to transparently switch between WinDivert (Windows), NetFilterQueue (Linux), and Divert Sockets (BSD/macOS).
- **Asynchronous by Design**: Full `asyncio` support with `recv_async()` and `send_async()`, utilizing high-performance Windows Overlapped I/O when available.
- **Modern Python**: Leverages Python 3.10+ features like **Structural Pattern Matching** (PEP 634) for elegant packet analysis.
- **WinDivert 2.2+ Power**: Full support for advanced Windows layers (FLOW, SOCKET, REFLECT) and rich metadata (PIDs, Flow IDs, etc.).
- **Zero Configuration**: Bundled WinDivert 64-bit binaries for Windows—no manual driver installation required.
- **Automatic Integrity**: Built-in logic for verifying and recalculating IPv4, TCP, UDP, and ICMP checksums.

---

## 🚀 Quick Start

### Basic Capture and Re-injection (Cross-Platform)

The `pydivert.PyDivert` class automatically selects the best backend for your OS.

```python
import pydivert

# Capture TCP packets to port 80 (HTTP)
# Works on Windows (WinDivert), Linux (iptables/NFQ), and FreeBSD (ipfw/Divert)
with pydivert.PyDivert("tcp.DstPort == 80") as w:
    for packet in w:
        print(f"Captured {packet.protocol} packet from {packet.src_addr}")
        
        # Modify the payload if needed
        if b"User-Agent" in packet.payload:
             packet.payload = packet.payload.replace(b"Python", b"PyDivert/4.0")
        
        # Re-inject the packet back into the network stack
        w.send(packet)
```

### High-Performance Asynchronous Loop

```python
import asyncio
import pydivert

async def main():
    async with pydivert.PyDivert("udp.DstPort == 53") as w:
        async for packet in w:
            print(f"Async DNS Query: {packet.payload.hex()}")
            await w.send_async(packet)

if __name__ == "__main__":
    asyncio.run(main())
```

---

## 🛠️ Installation

PyDivert requires **Administrator/Root** privileges to interact with the network stack.

```bash
# Using uv (Recommended)
uv add pydivert

# Using pip
pip install pydivert
```

---

## 🌍 Platform Compatibility

PyDivert aims for a "write once, run anywhere" experience, but some low-level features are platform-specific.

| Feature | Windows | Linux | FreeBSD | macOS |
| :--- | :---: | :---: | :---: | :---: |
| **Backend** | WinDivert 2.2 | NetFilterQueue | Divert Sockets | Divert Sockets |
| **Auto-Firewall** | ✅ (Built-in) | ✅ (iptables) | ✅ (ipfw) | ⚠️ (Manual PF) |
| **Async I/O** | ✅ (Overlapped) | ✅ (Threaded) | ✅ (Threaded) | ✅ (Threaded) |
| **Layers** | All (Net, Flow, etc.) | Network Only | Network Only | Network Only |
| **Bundled Driver**| ✅ Included | N/A | N/A | N/A |

---

## 🧩 Advanced Usage

### Structural Pattern Matching
Filter packets with the elegance of Python's `match/case`.

```python
from pydivert.packet import Packet
from pydivert.packet.tcp import TCPHeader

match packet:
    case Packet(tcp=TCPHeader(dst_port=443)):
        print("HTTPS Traffic")
    case Packet(ipv4=ip) if ip.ttl < 10:
        print(f"Low TTL packet from {packet.src_addr}")
```

### Packet Metadata
Access rich information about the packet's origin and state:
- `packet.direction`: `Direction.INBOUND` or `Direction.OUTBOUND`.
- `packet.is_loopback`: True if the packet originated locally.
- `packet.timestamp`: Precise capture time.
- `packet.interface`: Tuple of `(IfIdx, SubIfIdx)`.

---

## 🔍 Filter Compatibility Matrix

PyDivert 4.0.0 uses a transpiler to map WinDivert filter strings to native firewall rules (e.g., `iptables`, `ipfw`). While Windows supports the full expression language, Linux and BSD support a common subset at the kernel level.

| Filter Expression | Windows | Linux | BSD (FreeBSD) |
| :--- | :---: | :---: | :---: |
| `true` | ✅ | ✅ | ✅ |
| `tcp` / `udp` | ✅ | ✅ | ✅ |
| `tcp.DstPort == 80` | ✅ | ✅ | ✅ |
| `udp.SrcPort == 53` | ✅ | ✅ | ✅ |
| `or` / `||` (Simple ports) | ✅ | ✅ | ✅ |
| `ip.SrcAddr == 1.2.3.4` | ✅ | ❌* | ❌* |
| `tcp.PayloadLength > 0` | ✅ | ❌* | ❌* |
| `icmp` / `ip` | ✅ | ❌* | ❌* |
| `inbound` / `outbound` | ✅ | ❌* | ❌* |

*\* Note: Expressions marked with ❌ are not currently transpiled to kernel-level rules on Linux/BSD. These packets may still be filtered in user-space by the `Packet.matches()` method, but for performance reasons, it is recommended to use the supported subset for initial interception.*

---

## 🧪 Development & Testing

PyDivert uses `uv` for dependency management and `pytest` for testing. Most tests require **Administrator** (Windows) or **Root** (Linux/BSD) privileges to interact with the network stack.

### 1. Local Testing
To run tests on your current machine:
```bash
# Install dependencies
uv sync --all-extras

# Run tests (Requires Admin/Root)
uv run pytest
```

### 2. Multi-Platform Testing (Vagrant)
To ensure cross-platform compatibility, PyDivert includes a `Vagrantfile` that defines testing environments for **Windows 11, Ubuntu Linux, FreeBSD, and macOS**.

#### Full Automated Suite (Recommended)
We provide a helper script that automates the entire process: spinning up VMs, running tests, and generating a **consolidated coverage report** across all operating systems.
```bash
uv run python scripts/run-all-tests.py
```
This script will:
1. Run tests locally.
2. Bring up each Vagrant VM (`windows`, `linux`, `freebsd`, `macos`).
3. Execute the test suite inside each environment.
4. Collect and combine `.coverage` files from all platforms.
5. Generate a unified HTML report in `htmlcov/index.html`.

#### Manual VM Testing
You can also target a specific platform manually:
```bash
# Start a specific VM
vagrant up linux

# Run tests inside the VM
vagrant ssh linux -c "cd /home/vagrant/pydivert && uv run pytest"
```

### 3. Continuous Integration
The full test suite is automatically executed on every push to `main` and for all Pull Requests via GitHub Actions, covering Windows, Linux, and macOS.

---

## 📄 License

PyDivert is dual-licensed under the **LGPL-3.0-or-later** and **GPL-2.0-or-later** licenses, matching the licensing strategy of the WinDivert driver.
