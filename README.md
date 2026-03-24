# pydivert

[![github-actions](https://github.com/ffalcinelli/pydivert/actions/workflows/ci.yml/badge.svg)](https://github.com/ffalcinelli/pydivert/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/github/ffalcinelli/pydivert/master.svg)](https://codecov.io/gh/ffalcinelli/pydivert)
[![latest_release](https://img.shields.io/pypi/v/pydivert.svg)](https://pypi.python.org/pypi/pydivert)
[![python_versions](https://img.shields.io/pypi/pyversions/pydivert.svg)](https://pypi.python.org/pypi/pydivert)

Python bindings for [WinDivert](https://reqrypt.org/windivert.html), a Windows driver that allows user-mode applications to capture/modify/drop network packets sent to/from the Windows network stack.

## Requirements

- **Python 3.10+** (32 or 64 bit)
- **Windows Vista/7/8/10/11** or Windows Server 2008+ (32 or 64 bit)
- **Administrator Privileges**

## Installation

You can install PyDivert by running:

```bash
pip install pydivert
```

Alternatively, if you use [uv](https://github.com/astral-sh/uv):

```bash
uv add pydivert
```

WinDivert is bundled with PyDivert and does not need to be installed separately.

### WinDivert Version Compatibility

| PyDivert | WinDivert |
| --- | --- |
| 0.0.7 | 1.0.x or 1.1.x |
| 1.0.x | 1.1.8 (bundled) |
| 2.0.x | 1.1.8 (bundled) |
| 2.1.x | 1.3 (bundled) |
| 2.2.2 | 2.2.2 (bundled) |

## Getting Started

PyDivert consists of two main classes: `pydivert.WinDivert` and `pydivert.Packet`.

First, create a `WinDivert` object to start capturing network traffic and then call `.recv()` to receive the first `Packet` that was captured. By receiving packets, they are taken out of the Windows network stack and will not be sent out unless you take action. You can re-inject packets by calling `.send(packet)`.

```python
import pydivert

# Capture only TCP packets to port 80, i.e. HTTP requests.
with pydivert.WinDivert("tcp.DstPort == 80 and tcp.PayloadLength > 0") as w:
    for packet in w:
        print(packet)
        w.send(packet)
        break
```

Packets that are not matched by the filter will continue through the network stack as usual. The syntax for the filter language is described in the [WinDivert documentation](https://reqrypt.org/windivert-doc.html#filter_language).

## Features in WinDivert 2.2

PyDivert now supports the advanced features introduced in WinDivert 2.2, including:
- **New Layers**: Support for `FLOW`, `SOCKET`, and `REFLECT` layers.
- **Improved Packet Parsing**: Accurate handling of IP fragments and more protocol metadata.
- **Enhanced Address Metadata**: Timestamps, loopback flags, and process IDs (where supported by the layer).

## Packet Modification

`pydivert.Packet` provides properties to access and modify headers or payload.

```python
import pydivert

with pydivert.WinDivert("tcp.DstPort == 1234 or tcp.SrcPort == 80") as w:
    for packet in w:
        if packet.dst_port == 1234:
            print(">") # packet to the server
            packet.dst_port = 80
        if packet.src_port == 80:
            print("<") # reply from the server
            packet.src_port = 1234
        w.send(packet)
```

## API Reference

The API Reference Documentation for PyDivert can be found [here](https://ffalcinelli.github.io/pydivert/).

## Uninstalling

```bash
pip uninstall pydivert
```

If the WinDivert driver is still running, it will remove itself on the next reboot.
