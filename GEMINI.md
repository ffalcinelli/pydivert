# PyDivert Project Overview

PyDivert is a high-performance Python binding for **WinDivert**, a Windows driver that allows user-mode applications to capture, modify, and drop network packets sent to or from the Windows network stack.

## Core Architecture

- **`pydivert.WinDivert`**: The primary class for managing the WinDivert handle. It supports synchronous (`recv`/`send`) and asynchronous (`recv_ex`/`send_ex`) operations. It also provides static methods for programmatic driver management (`register`/`unregister`).
- **`pydivert.Packet`**: Represents a network packet and its associated metadata. It handles lazy parsing of protocol headers and manages the complex `WinDivertAddress` structure required for WinDivert 2.2 layers (Network, Flow, Socket, Reflect).
- **`pydivert.windivert_dll`**: A low-level `ctypes` wrapper for the bundled WinDivert binaries. It includes definitions for WinDivert structures like `WinDivertAddress` and `Overlapped`.
- **`pydivert.packet` subpackage**: Contains protocol-specific header implementations (IPv4, IPv6, TCP, UDP, ICMP) and logic for automatic checksum recalculation.

## Key Technologies

- **Python**: Supports 3.10+ (64-bit).
- **WinDivert**: Bundled version 2.2.2 (64-bit DLL and driver).
- **ctypes**: Used for zero-overhead interfacing with the native DLL.
- **uv**: Modern package management and build tool.
- **hatchling**: Build backend for PEP 517/621 with PEP 639 (SPDX) support.

## WinDivert 2.2 Support

PyDivert provides full access to WinDivert 2.2 features:
- **Advanced Layers**: Support for `Layer.NETWORK`, `Layer.FLOW`, `Layer.SOCKET`, and `Layer.REFLECT`.
- **Rich Metadata**: Access to process IDs (PIDs), endpoint IDs, loopback status, and impostor flags.
- **Overlapped I/O**: High-performance asynchronous capture and injection via Windows Overlapped I/O.
- **Programmatic Driver Management**: Methods to register and unregister the WinDivert driver service at runtime.

## Development Guide

### Prerequisites

- Windows 11 (64-bit).
- Administrator Privileges (required for WinDivert driver interaction).
- [uv](https://github.com/astral-sh/uv) installed.

### Building and Running

- **Install for development**:
  ```bash
  uv sync --extra test --extra docs --extra lint --extra typecheck
  ```
- **Run tests**:
  ```bash
  uv run pytest
  ```
  Note: Most tests require administrator privileges.
- **Linting & Type Checking**:
  ```bash
  uv run ruff check .
  uv run mypy .
  ```
- **Build documentation**:
  ```bash
  uv run python docs/build.py
  ```

### Testing on Non-Windows Platforms

Since **WinDivert** is Windows-only, a `Vagrantfile` is provided for local development on Linux/macOS.

- **Start the VM**: `vagrant up`
- **Run tests in the VM**:
  ```bash
  vagrant powershell -c '$env:UV_PROJECT_ENVIRONMENT="C:/pydivert_venv"; cd C:/pydivert; uv run pytest'
  ```

## License

PyDivert is dual-licensed under the **LGPL-3.0-or-later** and **GPL-2.0-or-later** licenses, matching the WinDivert driver's licensing strategy.
- [LICENSE-LGPL-3.0-or-later](LICENSE-LGPL-3.0-or-later)
- [LICENSE-GPL-2.0-or-later](LICENSE-GPL-2.0-or-later)
