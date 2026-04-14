# WinDivert Filter Language

This page provides a detailed reference for the WinDivert filter language syntax, which is used by PyDivert to capture specific network packets.

> [!NOTE]
> This documentation is based on the original [WinDivert Filter Language Documentation](https://reqrypt.org/windivert-doc.html#filter_language). Credits go to the original WinDivert authors for their excellent work and comprehensive documentation.

## Overview

A WinDivert filter is a string representing a boolean expression that is evaluated for each packet (or event) seen by the driver. If the expression evaluates to `true`, the packet is diverted to the PyDivert handle; otherwise, it is ignored.

## Syntax

### Boolean Operators

The filter language supports standard boolean operators with the following precedence (from highest to lowest):

1.  `!` (NOT)
2.  `&&` (AND)
3.  `||` (OR)

### Relational Operators

Relational operators can be used to compare fields with constants or other fields:

- `==` (equal)
- `!=` (not equal)
- `<` (less than)
- `>` (greater than)
- `<=` (less than or equal)
- `>=` (greater than or equal)

### Layers

Filters can target different layers. Each layer has specific fields available:

- `Layer.NETWORK` (default): Captures IP packets. Supported on all platforms.
- `Layer.FLOW`: Captures connection-oriented events. **(Windows only)**.
- `Layer.SOCKET`: Captures socket-level events. **(Windows only)**.
- `Layer.REFLECT`: Captures reflected events. **(Windows only)**.

---

## Multi-OS Filter Support

PyDivert 4.0.0 provides a unified filtering experience across Windows, Linux, and BSD/macOS. However, the underlying mechanisms for applying these filters differ significantly between operating systems.

### Kernel-Level Transpilation

On **Linux** and **BSD/macOS**, PyDivert uses a **transpiler** to convert the WinDivert filter string into native firewall rules:
- **Linux**: Transpiled to `iptables` rules that direct traffic to `NetFilterQueue`.
- **BSD (FreeBSD)**: Transpiled to `ipfw` rules that direct traffic to a `divert` socket.
- **macOS**: Requires manual configuration of `pf` rules to divert traffic to a port, though the transpiler can generate the appropriate configuration.

### User-Space Fallback Filtering

Not all WinDivert filter expressions can be directly mapped to kernel-level firewall rules on Linux or BSD. When a complex filter is used, PyDivert handles it in two stages:

1.  **Initial Interception (Kernel-level)**: A broad native firewall rule (e.g., `tcp` or `udp`) is applied to divert a subset of traffic to user-space.
2.  **Refined Filtering (User-space)**: The `Packet.matches()` method is used to evaluate the full WinDivert filter expression against each captured packet. If the packet doesn't match the refined filter, it is automatically re-injected or dropped based on the handle's configuration.

### Filter Compatibility Matrix

To optimize performance, it is recommended to use the subset of filters that can be transpiled directly to the kernel level.

| Filter Expression | Windows | Linux (Transpiled) | BSD (Transpiled) |
| :--- | :---: | :---: | :---: |
| `true` | ✅ | ✅ | ✅ |
| `tcp` / `udp` / `icmp` | ✅ | ✅ | ✅ |
| `tcp.DstPort == 80` | ✅ | ✅ | ✅ |
| `udp.SrcPort == 53` | ✅ | ✅ | ✅ |
| `or` / `||` (Simple ports) | ✅ | ✅ | ✅ |
| `ip.SrcAddr == 1.2.3.4` | ✅ | ✅ | ✅ |
| `ip.DstAddr == 8.8.8.8` | ✅ | ✅ | ✅ |
| `inbound` / `outbound` | ✅ | ✅ | ✅ |
| `tcp.PayloadLength > 0` | ✅ | ❌* | ❌* |

*\* Note: Expressions marked with ❌ are not currently transpiled to kernel-level rules. These packets will be filtered in user-space, which may impact performance for high-traffic environments.*

### Performance Considerations

For maximum performance on Linux and BSD, structure your filters to rely on transpiled fields as much as possible. This reduces the number of packets that must be context-switched from kernel-space to user-space only to be discarded by the fallback filter.

Example of an optimized filter for Linux:
`tcp.DstPort == 80 && tcp.PayloadLength > 0`
The kernel will only divert TCP traffic on port 80, and PyDivert will then check the payload length in user-space.


## Protocols and Fields

### IP Layer (IPv4 and IPv6)

Common fields for both IPv4 and IPv6:

- `ip.SrcAddr`: Source IP address.
- `ip.DstAddr`: Destination IP address.
- `ip.Protocol`: IP protocol number (e.g., 6 for TCP, 17 for UDP).
- `ip.TTL` / `ipv6.HopLimit`: Time-to-live or Hop limit.
- `ip.Length` / `ipv6.Length`: Total length of the packet.

Example: `ip.SrcAddr == 192.168.1.1`

### TCP

Fields available when the packet is TCP:

- `tcp.SrcPort`: Source port.
- `tcp.DstPort`: Destination port.
- `tcp.Flags`: TCP flags.
- `tcp.Syn`, `tcp.Ack`, `tcp.Fin`, `tcp.Rst`, `tcp.Psh`, `tcp.Urg`: Individual TCP flag booleans.
- `tcp.PayloadLength`: Length of the TCP payload in bytes.

Example: `tcp.DstPort == 80 && tcp.Syn`

### UDP

Fields available when the packet is UDP:

- `udp.SrcPort`: Source port.
- `udp.DstPort`: Destination port.
- `udp.Length`: UDP header + payload length.

Example: `udp.DstPort == 53` (DNS traffic)

### ICMP and ICMPv6

- `icmp.Type`: ICMP type.
- `icmp.Code`: ICMP code.
- `icmpv6.Type`: ICMPv6 type.
- `icmpv6.Code`: ICMPv6 code.

## Metadata and Flags

WinDivert provides several pseudo-fields representing metadata about the packet:

- `inbound`: Packet is inbound (coming from the network).
- `outbound`: Packet is outbound (sent by a local application).
- `loopback`: Packet is a loopback packet.
- `impostor`: Packet was injected by another application (e.g., another WinDivert handle).
- `ifIdx`: The interface index.
- `subIfIdx`: The sub-interface index.

Example: `outbound && tcp.DstPort == 443` (Outbound HTTPS traffic)

## Helper Functions

- `htons(port)`: Converts a port number to network byte order. (Usually not needed as WinDivert handles this automatically for constants).
- `ntohs(port)`: Converts a port number from network byte order.

## Advanced Examples

- **Capture all HTTP and HTTPS traffic**:
  `(tcp.DstPort == 80 || tcp.DstPort == 443) || (tcp.SrcPort == 80 || tcp.SrcPort == 443)`
- **Capture all traffic except from a specific IP**:
  `!(ip.SrcAddr == 1.2.3.4)`
- **Capture TCP SYN packets to port 22 (SSH)**:
  `tcp.DstPort == 22 && tcp.Syn && !tcp.Ack`
- **Capture loopback traffic**:
  `loopback`

For more information and a complete list of all available fields, please refer to the [official WinDivert documentation](https://reqrypt.org/windivert-doc.html#filter_language).
