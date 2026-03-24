# PyDivert Project Overview

PyDivert is a Python binding for **WinDivert**, a Windows driver that allows user-mode applications to capture, modify, and drop network packets sent to or from the Windows network stack.

## Core Architecture

- **`pydivert.WinDivert`**: The main class used to open a WinDivert handle, receive (`recv`), and send (`send`) packets. It supports being used as a context manager and an iterator.
- **`pydivert.Packet`**: Represents a network packet. It provides properties to access and modify headers (IPv4, IPv6, TCP, UDP, ICMP) and the payload.
- **`pydivert.windivert_dll`**: A low-level `ctypes` wrapper for the bundled WinDivert DLLs (`WinDivert32.dll` or `WinDivert64.dll`).
- **`pydivert.packet` subpackage**: Contains classes for different protocol headers (IP, TCP, UDP, ICMP).

## Key Technologies

- **Python**: Supports 3.10+.
- **uv**: Modern package management and build tool.
- **hatchling**: Build backend for PEP 517/621.
- **ctypes**: Used for interfacing with the native WinDivert DLL.
- **WinDivert**: Bundled version 2.2.2 (DLLs and drivers).

## Development Guide

### Prerequisites

- Windows Vista/7/8/10/11 or Windows Server 2008+.
- Administrator Privileges (required for WinDivert driver).
- [uv](https://github.com/astral-sh/uv) installed.

### Building and Running

- **Install for development**:
  ```bash
  uv sync --extra test --extra docs
  ```
- **Run tests**:
  ```bash
  uv run pytest
  ```
  Note: Many tests require administrator privileges because they interact with the WinDivert driver.
- **Build documentation**:
  ```bash
  uv run python docs/build.py
  ```

### Project Structure

- `pydivert/`: Main source code.
  - `packet/`: Protocol header implementations.
  - `tests/`: Test suite.
  - `windivert_dll/`: Bundled WinDivert binaries and `ctypes` bindings.
- `docs/`: MkDocs documentation source.
