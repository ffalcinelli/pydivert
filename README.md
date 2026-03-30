# PyDivert

[![github-actions](https://github.com/ffalcinelli/pydivert/actions/workflows/ci.yml/badge.svg)](https://github.com/ffalcinelli/pydivert/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/github/ffalcinelli/pydivert/main.svg)](https://codecov.io/gh/ffalcinelli/pydivert)
[![latest_release](https://img.shields.io/pypi/v/pydivert.svg)](https://pypi.python.org/pypi/pydivert)
[![python_versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://pypi.python.org/pypi/pydivert)
[![windows](https://img.shields.io/badge/os-windows%2011-blue.svg)](https://pypi.python.org/pypi/pydivert)
[![license](https://img.shields.io/pypi/l/pydivert.svg)](https://github.com/ffalcinelli/pydivert/blob/main/LICENSE)

**PyDivert** is a high-performance Python binding for [WinDivert](https://reqrypt.org/windivert.html), a Windows driver that allows user-mode applications to capture, modify, and drop network packets sent to or from the Windows network stack.

## Features

- **Capture** network packets matching a specific filter.
- **Modify** packet headers and payloads on the fly.
- **Drop** unwanted packets.
- **Inject** new or modified packets into the network stack.
- **WinDivert 2.2 Support**: Full access to advanced layers (`NETWORK`, `FLOW`, `SOCKET`, `REFLECT`) and metadata.
- **Asynchronous I/O**: High-performance packet capture and injection via Windows Overlapped I/O.
- **Programmatic Driver Management**: Register and unregister the WinDivert driver service at runtime.
- **Bundled Binaries**: The 64-bit WinDivert 2.2.2 DLL and driver are included.

## Requirements

- **Python 3.10+** (64-bit)
- **Windows 11** (64-bit)
- **Administrator Privileges** (required to interact with the WinDivert driver)

## Installation

Install PyDivert using `pip`:

```bash
pip install pydivert
```

Or using [uv](https://github.com/astral-sh/uv):

```bash
uv add pydivert
```

## Quick Start

### Basic Capture and Re-injection

```python
import pydivert

# Capture only TCP packets to port 80 (HTTP requests)
with pydivert.WinDivert("tcp.DstPort == 80") as w:
    for packet in w:
        print(f"Captured: {packet}")
        w.send(packet)  # Re-inject the packet back into the stack
```

When you iterate over the `WinDivert` object, the packet is **taken out** of the Windows network stack. It will not reach its destination unless you explicitly call `.send(packet)`.

### Packet Modification

```python
import pydivert

with pydivert.WinDivert("tcp.DstPort == 1234") as w:
    for packet in w:
        # Redirect traffic to port 80
        packet.dst_port = 80
        
        # WinDivert handles checksum recalculation automatically when sending
        w.send(packet)
```

## Advanced Usage

### High-Performance Asynchronous I/O

PyDivert supports Windows Overlapped I/O for high-performance, non-blocking packet capture:

```python
import pydivert
from pydivert.windivert_dll import Overlapped
import ctypes

# ... create and initialize a Windows Event ...
overlapped = Overlapped()
overlapped.hEvent = handle_to_windows_event

with pydivert.WinDivert("true", flags=pydivert.Flag.OVERLAPPED) as w:
    packet = w.recv_ex(overlapped=overlapped)
    if packet is None:
        # Operation is pending; wait for the event handle...
        pass
```

### Connection Tracking (FLOW Layer)

The `FLOW` layer allows you to capture connection events without seeing every packet, which is ideal for high-performance logging or firewalls.

```python
from pydivert import WinDivert, Layer

with WinDivert("true", layer=Layer.FLOW) as w:
    for event in w:
        print(f"Connection: {event.src_addr}:{event.src_port} -> {event.dst_addr}:{event.dst_port}")
        # Metadata like PIDs and Endpoint IDs are accessible via event.flow
        print(f"Process ID: {event.flow.process_id}")
```

### Programmatic Driver Management

You can programmatically manage the WinDivert driver service from your Python code:

```python
from pydivert import WinDivert

if not WinDivert.is_registered():
    WinDivert.register()
    print("Driver service registered successfully.")

# ... use WinDivert ...

# WinDivert.unregister()  # To remove the driver service if needed
```

## Development

To set up a development environment:

1. Clone the repository.
2. Install dependencies: `uv sync --extra test --extra docs`
3. Run tests (requires Admin): `uv run pytest`

For development on Linux/macOS, a `Vagrantfile` is provided to run the test suite on a Windows 11 VM:

```bash
vagrant up
vagrant powershell -c '$env:UV_PROJECT_ENVIRONMENT="C:/pydivert_venv"; cd C:/pydivert; uv run pytest'
```

## License

PyDivert is dual-licensed under the **LGPL-3.0-or-later** and **GPL-2.0-or-later** licenses to match the WinDivert driver's licensing strategy.

- [GNU Lesser General Public License v3.0 or later](LICENSE-LGPL-3.0-or-later)
- [GNU General Public License v2.0 or later](LICENSE-GPL-2.0-or-later)

See the [LICENSE](LICENSE) file for more details.
