# PyDivert

[![github-actions](https://github.com/ffalcinelli/pydivert/actions/workflows/ci.yml/badge.svg)](https://github.com/ffalcinelli/pydivert/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/github/ffalcinelli/pydivert/main.svg)](https://codecov.io/gh/ffalcinelli/pydivert)
[![latest_release](https://img.shields.io/pypi/v/pydivert.svg)](https://pypi.python.org/pypi/pydivert)
[![docs](https://img.shields.io/badge/docs-pdoc-blue.svg)](https://ffalcinelli.github.io/pydivert/)
[![python_versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://pypi.python.org/pypi/pydivert)
[![windows](https://img.shields.io/badge/os-windows%2011-blue.svg)](https://pypi.python.org/pypi/pydivert)
[![license](https://img.shields.io/pypi/l/pydivert.svg)](https://github.com/ffalcinelli/pydivert/blob/main/LICENSE)

**PyDivert** is a powerful Python binding for [WinDivert](https://reqrypt.org/windivert.html), a Windows driver that allows user-mode applications to capture, modify, and drop network packets sent to or from the Windows network stack.

## Features

- **Capture** network packets matching a specific filter.
- **Modify** packet headers and payloads on the fly.
- **Drop** unwanted packets.
- **Inject** new or modified packets into the network stack.
- **Support for WinDivert 2.2+** advanced features (FLOW, SOCKET, and REFLECT layers).
- **Bundled Binaries**: No need to manually install WinDivert; the 64-bit DLL and driver are included.

## Requirements

- **Python 3.10+** (64-bit)
- **Windows 11** (64-bit)
- **Administrator Privileges** (required to interact with the WinDivert driver)

> [!NOTE]
> Windows Server is currently untested but likely works if it meets the architecture requirements.

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

The main entry points are `pydivert.WinDivert` for capturing and `pydivert.Packet` for manipulation.

> [!TIP]
> All code examples in this README are verified by automated integration tests in `pydivert/tests/test_readme_examples.py`.

### Basic Capture and Re-injection

```python
import pydivert

# Capture only TCP packets to port 80 (HTTP requests)
with pydivert.WinDivert("tcp.DstPort == 80") as w:
    for packet in w:
        print(f"Captured: {packet}")
        w.send(packet)  # Re-inject the packet back into the stack
```

When you call `.recv()` (or iterate over the `WinDivert` object), the packet is **taken out** of the Windows network stack. It will not reach its destination unless you explicitly call `.send(packet)`.

### Packet Modification

You can easily modify packet headers and recalculate checksums automatically.

```python
import pydivert

with pydivert.WinDivert("tcp.DstPort == 1234") as w:
    for packet in w:
        # Redirect traffic to port 80
        packet.dst_port = 80
        
        # WinDivert handles checksum recalculation by default when sending
        w.send(packet)
```

## Common Use Cases

### 1. Simple Firewall (Dropping Packets)
By simply not calling `.send(packet)`, the packet is effectively dropped and never reaches its destination.

```python
import pydivert

# Block all traffic from a specific IP address
with pydivert.WinDivert("ip.SrcAddr == 1.2.3.4") as w:
    for packet in w:
        print(f"Blocking packet from {packet.src_addr}")
        # Packet is dropped here
```

### 2. Payload Inspection and Modification
You can inspect or modify the raw bytes of the packet payload.

```python
import pydivert

# Filter for TCP packets with payload
with pydivert.WinDivert("tcp.PayloadLength > 0") as w:
    for packet in w:
        if b"secret-token" in packet.payload:
            print("Sensitive data detected!")
            # Redact the token
            packet.payload = packet.payload.replace(b"secret-token", b"REDACTED")
        w.send(packet)
```

### 3. Traffic Logging
Log detailed information about network flows.

```python
import pydivert

with pydivert.WinDivert("tcp or udp") as w:
    for packet in w:
        direction = "OUT" if packet.is_outbound else "IN "
        print(f"[{direction}] {packet.src_addr}:{packet.src_port} -> "
              f"{packet.dst_addr}:{packet.dst_port} ({len(packet.payload)} bytes)")
        w.send(packet)
```

## Common Packet Properties

The `pydivert.Packet` object provides easy access to common protocol fields:

- **IP Layer**: `packet.src_addr`, `packet.dst_addr`, `packet.ip.ttl`
- **TCP/UDP Layer**: `packet.src_port`, `packet.dst_port`
- **Payload**: `packet.payload` (bytes)
- **Metadata**: Captured `Packet` objects include additional metadata provided by WinDivert 2.2:
  - **`timestamp`**: The time when the packet was captured (uses `QueryPerformanceCounter`).
  - **`is_loopback`**: `True` if the packet is a loopback packet.
  - **`is_impostor`**: `True` if the packet was injected by another driver.
  - **`is_sniffed`**: `True` if the packet was captured in sniff mode.
  - **`interface`**: The interface index where the packet was captured.
  - **Checksum status**: `ip_checksum`, `tcp_checksum`, and `udp_checksum` flags indicate if the hardware offloaded checksums are valid.

Detailed protocol headers are available through `packet.ipv4`, `packet.ipv6`, `packet.tcp`, `packet.udp`, and `packet.icmp`.

## Asynchronous IO

PyDivert supports Windows Overlapped IO for asynchronous packet capture and injection via `recv_ex()` and `send_ex()`:

```python
import pydivert
from pydivert.windivert_dll import Overlapped
import ctypes

# ... create event, initialize Overlapped structure ...
overlapped = Overlapped()
# overlapped.hEvent = ... windows event handle ...

with pydivert.WinDivert("true") as w:
    packet = w.recv_ex(overlapped=overlapped)
    if packet is None:
        # Operation is pending (ERROR_IO_PENDING)
        # ... wait for event ...
        pass
```

## Advanced Usage

### WinDivert Layers

WinDivert supports different layers for capturing different types of traffic:

- `Layer.NETWORK` (default): Captures IP packets.
- `Layer.FLOW`: Captures connection events (useful for logging connections without seeing every packet).
- `Layer.SOCKET`: Captures socket-level events.

```python
from pydivert import WinDivert, Layer

with WinDivert("true", layer=Layer.FLOW) as w:
    for event in w:
        print(f"Connection event: {event}")
```

### Flags

You can customize the behavior using flags:

- `Flag.SNIFF`: Capture packets without diverting them (they still reach their destination).
- `Flag.DROP`: Drop packets by default.
- `Flag.OVERLAPPED`: Use asynchronous (overlapped) I/O.

```python
from pydivert import WinDivert, Flag

with WinDivert("tcp.DstPort == 80", flags=Flag.SNIFF) as w:
    for packet in w:
        print(f"Sniffed: {packet}")
```

## WinDivert Version Compatibility

| PyDivert | WinDivert |
| --- | --- |
| 0.0.7 | 1.0.x or 1.1.x |
| 1.0.x | 1.1.8 (bundled) |
| 2.0.x | 1.1.8 (bundled) |
| 2.1.x | 1.3 (bundled) |
| 3.0.0+ | 2.2.2 (bundled) - Breaking changes for full 2.2 support |

## Breaking Changes in 3.0.0

PyDivert 3.0.0 introduces full support for WinDivert 2.2's advanced metadata, which required several backward-incompatible changes to the internal API:

- **Packet Constructor**: The `Packet` class's `__init__` now accepts additional metadata fields (`layer`, `event`, `flow`, `socket`, `reflect`). The `interface` parameter is now optional and defaults to `(0, 0)`.
- **Internal Metadata**: When receiving packets from non-`NETWORK` layers (like `FLOW` or `SOCKET`), the `Packet` object now preserves and allows re-injecting the full metadata structure.
- **`wd_addr` Property**: This property now returns a full `WINDIVERT_ADDRESS` for any supported layer, not just the network layer.

If you are manually creating `Packet` objects or relying on the exact signature of the `Packet` constructor, you may need to update your code.

## Security

For information on supported versions, reporting vulnerabilities, and security best practices, please see our [Security Policy](SECURITY.md).

## Development

To set up a development environment:

1. Clone the repository.
2. Install dependencies: `uv sync --extra test --extra docs`
3. Run tests (requires Admin): `uv run pytest`

### Testing on other Operating Systems (using Vagrant)

Since PyDivert requires Windows and Administrator privileges, you can use **Vagrant** to run the test suite on a Windows 11 virtual machine from a Linux or macOS host.

**Prerequisites:**
- [Vagrant](https://www.vagrantup.com/)
- [VirtualBox](https://www.virtualbox.org/)

**Steps:**

1.  **Bring up the VM:**
    ```bash
    vagrant up
    ```
    This will download a Windows 11 box, provision it with `uv`, and install all necessary dependencies.

2.  **Run the tests:**
    ```bash
    vagrant powershell -c '$env:UV_PROJECT_ENVIRONMENT="C:/pydivert_venv"; cd C:/pydivert; uv run pytest'
    ```

3.  **Interactive Session:**
    If you need to explore the environment manually:
    ```bash
    vagrant powershell
    ```

## API Reference

The full API documentation is available at [https://ffalcinelli.github.io/pydivert/](https://ffalcinelli.github.io/pydivert/).

## License

PyDivert is dual-licensed under the **LGPL-3.0-or-later** and **GPL-2.0-or-later** licenses to match the WinDivert driver's licensing strategy.

- [GNU Lesser General Public License v3.0 or later](LICENSE-LGPL-3.0-or-later)
- [GNU General Public License v2.0 or later](LICENSE-GPL-2.0-or-later)

See the [LICENSE](LICENSE) file for more details.
