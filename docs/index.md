# PyDivert Documentation

**PyDivert** is a Python binding for **WinDivert**, a Windows driver that allows user-mode applications to capture, modify, and drop network packets sent to or from the Windows network stack.

## WinDivert 2.2 Features

The current version of PyDivert bundles **WinDivert 2.2.2** and supports:

- **New Layers**: Support for `NETWORK`, `NETWORK_FORWARD`, `FLOW`, `SOCKET`, and `REFLECT` layers.
- **Packet Metadata**: Capture timestamps, loopback status, and impostor status.
- **Improved Protocol Support**: Handles IPv4, IPv6, TCP, UDP, ICMP, and ICMPv6.
- **Checksum Calculation**: Automated checksum calculation for IPv4, TCP, and UDP headers.

## Basic Usage

The most common way to use PyDivert is as a context manager:

```python
import pydivert

# Capture only TCP packets to port 80
with pydivert.WinDivert("tcp.DstPort == 80") as w:
    for packet in w:
        print(f"Captured packet from {packet.src_addr} to {packet.dst_addr}")
        # Modify the packet if needed
        # packet.tcp.dst_port = 8080
        w.send(packet)
```

## Packet Metadata

Captured `Packet` objects now include additional metadata provided by WinDivert 2.2:

- **`timestamp`**: The time when the packet was captured (uses `QueryPerformanceCounter`).
- **`is_loopback`**: `True` if the packet is a loopback packet.
- **`is_impostor`**: `True` if the packet was injected by another driver.
- **`is_sniffed`**: `True` if the packet was captured in sniff mode.
- **Checksum status**: `ip_checksum`, `tcp_checksum`, and `udp_checksum` flags indicate if the hardware offloaded checksums are valid.

## Installation

```bash
pip install pydivert
```

Alternatively, with **uv**:

```bash
uv add pydivert
```

For more detailed information, please refer to the [API Reference](api.md).
