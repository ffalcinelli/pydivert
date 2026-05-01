# PyDivert

[![github-actions](https://github.com/ffalcinelli/pydivert/actions/workflows/ci.yml/badge.svg)](https://github.com/ffalcinelli/pydivert/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/github/ffalcinelli/pydivert/main.svg)](https://codecov.io/gh/ffalcinelli/pydivert)
[![latest_release](https://img.shields.io/pypi/v/pydivert.svg)](https://pypi.python.org/pypi/pydivert)
[![docs](https://img.shields.io/badge/docs-pdoc-blue.svg)](https://ffalcinelli.github.io/pydivert/)
[![python_versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://pypi.python.org/pypi/pydivert)
[![windows](https://img.shields.io/badge/os-windows%2011-blue.svg)](https://pypi.python.org/pypi/pydivert)
[![license](https://img.shields.io/pypi/l/pydivert.svg)](https://github.com/ffalcinelli/pydivert/blob/main/LICENSE)
[![snyk](https://img.shields.io/badge/snyk-security-violet)](https://security.snyk.io/package/pip/pydivert)

**PyDivert** is a high-performance, cross-platform Python binding for capturing, modifying, and dropping network packets. It supports **Windows** via [WinDivert](https://reqrypt.org/windivert.html) and **Linux** via **eBPF (CO-RE)**.

## Features

- **Cross-Platform**: Unified API for Windows (WinDivert) and Linux (eBPF).
- **Capture** network packets matching a specific filter.
- **Modify** packet headers and payloads on the fly.
- **Drop** unwanted packets.
- **Inject** new or modified packets into the network stack.
- **Modern Python Support**: Full integration with `asyncio` and Structural Pattern Matching (PEP 634).
- **Support for WinDivert 2.2+** advanced features (FLOW, SOCKET, and REFLECT layers).
- **Bundled Binaries**: No need to manually install WinDivert on Windows; the 64-bit DLL and driver are included.

## Requirements

- **Python 3.10+** (64-bit)
- **Windows 11** (64-bit) or **Linux** (with eBPF support, kernel 5.8+)
- **Administrator/Root Privileges** (required to interact with network drivers)

> [!NOTE]
> Windows Server is currently untested but likely works if it meets the architecture requirements. On Linux, `libbpf` and a modern kernel are required.

## Installation

Install PyDivert using `pip`:

```bash
pip install pydivert
```

For Linux eBPF support, install with the `linux` extra:

```bash
pip install "pydivert[linux]"
```

Or using [uv](https://github.com/astral-sh/uv):

```bash
uv add pydivert --extra linux
```

## Quick Start

The main entry points are `pydivert.Divert` for cross-platform capturing and `pydivert.Packet` for manipulation.

> [!TIP]
> All code examples in this README are verified by automated integration tests in `pydivert/tests/test_readme_examples.py`.

### Basic Capture and Re-injection (Cross-Platform)

```python
import pydivert

# Capture only TCP packets to port 80 (HTTP requests)
with pydivert.Divert("tcp.DstPort == 80") as diverter:
    for packet in diverter:
        print(f"Captured: {packet}")
        diverter.send(packet)  # Re-inject the packet back into the stack
```

When you call `.recv()` (or iterate over the capture object), the packet is **taken out** of the network stack. It will not reach its destination unless you explicitly call `.send(packet)`.

### First-Class `asyncio` Support

PyDivert 4.0 supports `asyncio` natively using modern `async with` and `async for` syntax.

```python
import asyncio
import pydivert

async def main():
    # Asynchronously capture packets
    async with pydivert.Divert("tcp.DstPort == 80") as diverter:
        async for packet in diverter:
            print(f"Async captured: {packet}")
            await diverter.send_async(packet)

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

with pydivert.Divert("tcp") as diverter:
    for packet in diverter:
        match packet:
            case Packet(tcp=TCPHeader(dst_port=80)):
                print("HTTP Traffic")
            case Packet(tcp=TCPHeader(dst_port=443)):
                print("HTTPS Traffic")
        diverter.send(packet)
```

### 2. Simple Firewall (Dropping Packets)
By simply not calling `.send(packet)`, the packet is effectively dropped.

```python
import pydivert

# Block all traffic from a specific IP address
with pydivert.Divert("ip.SrcAddr == 1.2.3.4") as diverter:
    for packet in diverter:
        print(f"Blocking packet from {packet.src_addr}")
        # Packet is dropped here
```

### 3. Payload Modification
You can inspect or modify the raw bytes of the packet payload.

```python
import pydivert

# Filter for TCP packets with payload
with pydivert.Divert("tcp.PayloadLength > 0") as diverter:
    for packet in diverter:
        if b"secret-token" in packet.payload:
            # Redact the token
            packet.payload = packet.payload.replace(b"secret-token", b"REDACTED")
        diverter.send(packet)
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

## Filter Language

Divert uses the WinDivert filter language to select which packets to capture. For a detailed reference on the syntax and available fields, see the [Filter Language Guide](#windivert-filter-language).

For the original technical reference, please visit the [official WinDivert documentation](https://reqrypt.org/windivert-doc.html#filter_language).

## WinDivert/eBPF Version Compatibility

| Divert | Backend |
| --- | --- |
| 4.0.0+ | WinDivert 2.2.2 (bundled) / Linux eBPF (CO-RE) |
| 3.0.0+ | WinDivert 2.2.2 (bundled) - Full support for modern metadata and layers |

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

PyDivert is dual-licensed under [LGPL-3.0-or-later](https://github.com/ffalcinelli/pydivert/blob/main/LICENSE-LGPL-3.0-or-later) and [GPL-2.0-or-later](https://github.com/ffalcinelli/pydivert/blob/main/LICENSE-GPL-2.0-or-later).

## Security

PyDivert is committed to security and uses [Snyk](https://snyk.io/) for continuous vulnerability scanning. For more details on our security practices and how to report vulnerabilities, please refer to the [Security Policy](#security-policy).
