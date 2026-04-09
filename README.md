# PyDivert

[![github-actions](https://github.com/ffalcinelli/pydivert/actions/workflows/ci.yml/badge.svg)](https://github.com/ffalcinelli/pydivert/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/github/ffalcinelli/pydivert/main.svg)](https://codecov.io/gh/ffalcinelli/pydivert)
[![latest_release](https://img.shields.io/pypi/v/pydivert.svg)](https://pypi.python.org/pypi/pydivert)
[![docs](https://img.shields.io/badge/docs-pdoc-blue.svg)](https://ffalcinelli.github.io/pydivert/)
[![python_versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://pypi.python.org/pypi/pydivert)
[![windows](https://img.shields.io/badge/os-windows%2011-blue.svg)](https://pypi.python.org/pypi/pydivert)
[![license](https://img.shields.io/pypi/l/pydivert.svg)](https://github.com/ffalcinelli/pydivert/blob/main/LICENSE)
[![Snyk](https://snyk.io/test/github/ffalcinelli/pydivert/badge.svg)](https://snyk.io/test/github/ffalcinelli/pydivert)

**PyDivert** is a powerful Python binding for [WinDivert](https://reqrypt.org/windivert.html), a Windows driver that allows user-mode applications to capture, modify, and drop network packets sent to or from the Windows network stack. Starting from version 3.2.0, it also provides an abstract layer for cross-platform support on Linux (via NetFilterQueue) and BSD (via Divert sockets).

## Features

- **Cross-Platform Support**: Use the same API on Windows, Linux, and BSD.
- **Capture** network packets matching a specific filter (with a full WinDivert filter transpiler).
- **Modify** packet headers and payloads on the fly.
- **Drop** unwanted packets.
- **Inject** new or modified packets into the network stack.
- **Modern Python Support**: Full integration with `asyncio` and Structural Pattern Matching (PEP 634).
- **Support for WinDivert 2.2+** advanced features (FLOW, SOCKET, and REFLECT layers).
- **Bundled Binaries**: No need to manually install WinDivert on Windows; the 64-bit DLL and driver are included.

## Requirements

- **Python 3.10+** (64-bit)
- **Windows 11**, **Linux**, or **BSD/macOS**
- **Administrator/Root Privileges** (required to interact with the network stack)

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

The main entry point for cross-platform usage is `pydivert.PyDivert`. On Windows, you can also use the specialized `pydivert.WinDivert` class.

### Basic Capture and Re-injection (Cross-Platform)

```python
import pydivert

# Capture only TCP packets to port 80 (HTTP requests)
# On Windows this uses WinDivert, on Linux it uses NetFilterQueue
with pydivert.PyDivert("tcp.DstPort == 80") as w:
    for packet in w:
        print(f"Captured: {packet}")
        w.send(packet)  # Re-inject the packet back into the stack
```

When you call `.recv()` (or iterate over the `WinDivert` object), the packet is **taken out** of the Windows network stack. It will not reach its destination unless you explicitly call `.send(packet)`.

### First-Class `asyncio` Support

PyDivert 3.0+ supports `asyncio` natively using modern `async with` and `async for` syntax.

```python
import asyncio
import pydivert

async def main():
    # Asynchronously capture packets
    async with pydivert.WinDivert("tcp.DstPort == 80") as w:
        async for packet in w:
            print(f"Async captured: {packet}")
            await w.send_async(packet)

if __name__ == "__main__":
    asyncio.run(main())
```

## Common Use Cases

### 1. Structural Pattern Matching (PEP 634)
Filter and analyze packets using clean `match/case` syntax.

```python
import pydivert
from pydivert.packet import Packet
from pydivert.packet.tcp import TCPHeader

with pydivert.WinDivert("tcp") as w:
    for packet in w:
        match packet:
            case Packet(tcp=TCPHeader(dst_port=80)):
                print("HTTP Traffic")
            case Packet(tcp=TCPHeader(dst_port=443)):
                print("HTTPS Traffic")
        w.send(packet)
```

### 2. Simple Firewall (Dropping Packets)
By simply not calling `.send(packet)`, the packet is effectively dropped.

```python
import pydivert

# Block all traffic from a specific IP address
with pydivert.WinDivert("ip.SrcAddr == 1.2.3.4") as w:
    for packet in w:
        print(f"Blocking packet from {packet.src_addr}")
        # Packet is dropped here
```

### 3. Payload Modification
You can inspect or modify the raw bytes of the packet payload.

```python
import pydivert

# Filter for TCP packets with payload
with pydivert.WinDivert("tcp.PayloadLength > 0") as w:
    for packet in w:
        if b"secret-token" in packet.payload:
            # Redact the token
            packet.payload = packet.payload.replace(b"secret-token", b"REDACTED")
        w.send(packet)
```

## Packet Integrity and Checksums

PyDivert can verify and recalculate network checksums automatically.

- **`packet.is_checksum_valid`**: Returns `True` if all checksums (IP, TCP, UDP, ICMP) in the packet are correct.
- **`packet.recalculate_checksums()`**: Recalculates all checksums based on the current header and payload values.

```python
if not packet.is_checksum_valid:
    print("Corrupted packet detected!")
    packet.recalculate_checksums()
```

## Common Packet Properties

The `pydivert.Packet` object provides easy access to common fields:

- **IP Layer**: `packet.src_addr`, `packet.dst_addr`, `packet.ip.ttl`, `packet.ip.protocol`
- **TCP/UDP Layer**: `packet.src_port`, `packet.dst_port`, `packet.tcp.flags`
- **Payload**: `packet.payload` (bytes)
- **Metadata**:
  - **`timestamp`**: Capture time (QueryPerformanceCounter).
  - **`is_loopback`**, **`is_impostor`**, **`is_sniffed`**: Boolean flags.
  - **`interface`**: Index of the capture interface.
  - **`direction`**: `Direction.INBOUND` or `Direction.OUTBOUND`.

Detailed protocol headers are available through `packet.ipv4`, `packet.ipv6`, `packet.tcp`, `packet.udp`, and `packet.icmp`.

## Advanced Usage

### WinDivert Layers

- `Layer.NETWORK` (default): IP packets.
- `Layer.FLOW`: Connection events.
- `Layer.SOCKET`: Socket-level events.
- `Layer.REFLECT`: Reflected events.

### Flags

- `Flag.SNIFF`: Monitor mode (sniffing).
- `Flag.DROP`: Drop packets by default.
- `Flag.FRAGMENTS`: Capture all IP fragments.
- `Flag.RECV_ONLY` / `Flag.SEND_ONLY`: Restricted handles.

## WinDivert Version Compatibility

| PyDivert | WinDivert |
| --- | --- |
| 3.0.0+ | 2.2.2 (bundled) - Full support for modern metadata and layers |

## Development

1. Clone the repository.
2. Install dependencies: `uv sync --extra test --extra docs`
3. Run tests (requires Admin): `uv run pytest`

### Testing with Vagrant

Since WinDivert requires Windows, use **Vagrant** to run tests on a Windows 11 VM:

```bash
vagrant up
vagrant powershell -c '$env:UV_PROJECT_ENVIRONMENT="C:/pydivert_venv"; cd C:/pydivert; uv run pytest'
```

## API Reference

The full API documentation is available at [https://ffalcinelli.github.io/pydivert/](https://ffalcinelli.github.io/pydivert/).

## License

PyDivert is dual-licensed under **LGPL-3.0-or-later** and **GPL-2.0-or-later**.
