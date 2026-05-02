# PyDivert Project Overview

PyDivert is a high-performance, cross-platform Python binding for capturing, modifying, and dropping network packets. It supports **Windows** (via WinDivert) and **Linux** (via eBPF).

## Core Architecture

- **`pydivert.Divert`**: The primary class for managing the capture handle. It acts as a cross-platform facade, routing to `WinDivert` on Windows and `EBPFDivert` on Linux. It supports synchronous (`recv`/`send`) and asynchronous (`recv_async`/`send_async`) operations.
- **`pydivert.EBPFDivert`**: The Linux counterpart using **eBPF (CO-RE)**. It provides a compatible API with `WinDivert` for seamless cross-platform usage.
- **`pydivert.Packet`**: Represents a network packet and its associated metadata. It handles lazy parsing of protocol headers and manages complex metadata across both backends.
- **`pydivert.windivert_dll`**: A low-level `ctypes` wrapper for the bundled WinDivert binaries (Windows only).
- **`pydivert.bpf`**: eBPF bytecode and Python bindings for Linux packet interception.
- **`pydivert.packet` subpackage**: Contains protocol-specific header implementations (IPv4, IPv6, TCP, UDP, ICMP) and logic for automatic checksum recalculation.

## Key Technologies

- **Python**: Supports 3.10+ (64-bit).
- **WinDivert**: Bundled version 2.2.2 (Windows).
- **eBPF (CO-RE)**: Native Linux kernel integration for high-performance packet manipulation.
- **ctypes / cffi**: Used for zero-overhead interfacing with native components.
- **uv**: Modern package management and build tool.

## Cross-Platform Features

PyDivert 4.0 provides a unified interface for packet manipulation:
- **Unified Filter Language**: Use the same WinDivert-style filters on both Windows and Linux.
- **Advanced Metadata**: Access to process IDs (PIDs), endpoint IDs, loopback status, and more.
- **Asyncio Support**: Native asynchronous capture and injection on both platforms.
- **Physical Verification**: Automated integration tests ensure behavioral parity between the backends.

## Development Guide

### Prerequisites

- [Vagrant](https://www.vagrantup.com/) and [VirtualBox](https://www.virtualbox.org/) installed (Recommended for safe testing).
- [uv](https://github.com/astral-sh/uv) installed (Local development).
- **Elevated Privileges**: PyDivert requires root/Administrator privileges to interact with network drivers and eBPF.

### Building and Running

- **Install for development**:
  ```bash
  uv sync --extra test --extra docs --extra lint --extra typecheck
  ```
- **Run tests**:
  Testing PyDivert requires elevated privileges and interacts directly with the network stack. It is **strongly recommended** to run tests inside the provided Vagrant virtual machines to avoid compromising your host system (see the "Testing in Virtual Environments" section below).
- **Linting & Type Checking**:
  ```bash
  uv run ruff check .
  uv run ty check .
  ```
- **Build documentation**:
  ```bash
  uv run --extra docs python docs/build.py
  ```

### Testing in Virtual Environments (Recommended)

To ensure a safe and consistent environment with the required elevated privileges, use the provided Vagrant virtual machines.

- **Initialize VMs**: `vagrant up`
- **Run Linux Tests (eBPF)**:
  ```bash
  # Requires root privileges inside the VM
  vagrant ssh linux -c "sudo /pydivert/.venv/bin/python -m pytest /pydivert/pydivert/tests"
  ```
- **Run Windows Tests (WinDivert)**:
  ```bash
  # Requires Administrator privileges (default in Vagrant Windows boxes)
  vagrant winrm windows -c "C:\pydivert\.venv\Scripts\python.exe -m pytest C:\pydivert\pydivert\tests"
  ```

## License

PyDivert is dual-licensed under the **LGPL-3.0-or-later** and **GPL-2.0-or-later** licenses, matching the WinDivert driver's licensing strategy.
- [LICENSE-LGPL-3.0-or-later](LICENSE-LGPL-3.0-or-later)
- [LICENSE-GPL-2.0-or-later](LICENSE-GPL-2.0-or-later)

## CI/CD & Security Mandates

To maintain security and reliability in the project's automation, the following rules MUST be followed:
- **Immutable Pinning**: All GitHub Actions in `.github/workflows/` must be pinned to 40-character commit SHAs (e.g., `actions/checkout@11bd7190...`). Using mutable tags (like `@v6`) is forbidden to prevent supply-chain attacks.
- **Modern Runtimes**: GitHub Actions must use the Node 24 runtime (or the current stable version) to avoid deprecated and insecure environments.
- **Workflow Separation**: CI testing and Release processes must remain in separate workflow files (`ci.yml` and `release.yml`) to ensure a clear distinction between development validation and production delivery.
- **Verification**: The distributed wheel must include the `pydivert/tests` package to enable post-installation verification on destination machines.
