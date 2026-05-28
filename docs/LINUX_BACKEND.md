# Linux (eBPF) Backend

PyDivert 4.0 introduces a high-performance Linux backend using **eBPF (CO-RE)**. This allows PyDivert to provide a near-identical experience to the Windows WinDivert backend while leveraging native Linux kernel features.

## Architecture

On Linux, PyDivert attaches eBPF programs to the **Traffic Control (TC)** subsystem. These programs are executed for every packet entering or leaving the system's network interfaces.

- **Ingress**: Captured using a TC ingress hook.
- **Egress**: Captured using a TC egress hook.
- **Loop Prevention**: Packets re-injected by PyDivert are marked with a priority-aware socket mark (`SO_MARK`). This allows lower-priority handles to capture packets re-injected by higher-priority handles, matching WinDivert's multi-handle semantics.

## Multi-Instance Support

PyDivert on Linux supports multiple concurrent instances by leveraging the kernel's native **TC Chaining**.

- **Priority Chaining**: When multiple handles are opened, the kernel executes their BPF programs sequentially based on their priority.
- **Dynamic Priorities**: If you use the default priority (`0`), PyDivert automatically assigns a unique TC priority that places the new instance after existing ones.
- **Surgical Cleanup**: Calling `Divert.unregister()` (or closing a handle) only removes the specific eBPF filters created by PyDivert, leaving other network software's TC configurations intact.

## Layer Translation

WinDivert layers are translated to Linux eBPF as follows:

| WinDivert Layer | Linux eBPF Implementation | Behavior |
| --- | --- | --- |
| `Layer.NETWORK` | TC Ingress/Egress hooks | Full support (Capture, Modify, Drop, Inject). |
| `Layer.FLOW` | TC hooks + Event mapping | **Sniff-only**. Connection events are captured, but packets cannot be blocked at this layer. |
| `Layer.SOCKET` | TC hooks + Event mapping | **Sniff-only**. Socket-level metadata is emulated where possible. |
| `Layer.REFLECT` | N/A | **Not supported** on Linux. |

## Flag Translation

| WinDivert Flag | eBPF Implementation |
| --- | --- |
| `Flag.SNIFF` | The BPF program returns `TC_ACT_OK`, allowing the original packet to proceed while sending a copy to PyDivert. |
| `Flag.DROP` | The BPF program returns `TC_ACT_SHOT`, causing the kernel to immediately discard the packet. |
| `Flag.FRAGMENTS` | Supported. BPF logic handles L3 detection for fragmented packets. |
| `Flag.RECV_ONLY` | Captures packets but disables the raw socket used for re-injection. |
| `Flag.SEND_ONLY` | Disables TC hook attachment; used only for packet injection. |

## Feature Parity and Differences

### Unified Filter Language
PyDivert transpiles WinDivert-style filter strings into BPF bytecode instructions. This means you can use the same `tcp.DstPort == 80` filters on both platforms.

### Interface Selection
Unlike WinDivert which captures system-wide, the Linux backend can be restricted to specific interfaces:
```python
# Linux-only: Capture only on 'eth0'
with pydivert.Divert("true", interfaces=["eth0"]) as w:
    ...
```

### Checksums
PyDivert handles checksum recalculation in Python before re-injecting packets. While BPF can recalculate checksums, doing it in Python ensures consistent behavior across both backends when headers are modified.

### Root Privileges
Interacting with TC and loading eBPF programs requires `CAP_NET_ADMIN` and `CAP_BPF` (or simply root privileges).

## Performance
The Linux backend uses **Ring Buffers** (`BPF_MAP_TYPE_RINGBUF`) for zero-copy data transfer between the kernel and user space, ensuring minimal overhead even under heavy load.
