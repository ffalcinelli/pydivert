# Linux (eBPF) Backend Guide

PyDivert introduces a high-performance Linux backend utilizing **eBPF (CO-RE)**. This allows PyDivert to offer an interface matching the Windows WinDivert API while exploiting native Linux kernel features.

> [!WARNING]
> Linux support via eBPF is experimental and should not be used in production environments.

---

## 1. Architecture & Hooks

On Linux, PyDivert attaches eBPF classifier programs to the **Traffic Control (TC)** subsystem on targeted network interfaces.

- **Ingress Hook**: Intercepts packets entering the interface.
- **Egress Hook**: Intercepts packets leaving the interface.
- **Ring Buffers**: zero-copy data transfer is achieved using `BPF_MAP_TYPE_RINGBUF` maps, streaming packets to the user-space Python runtime with minimal overhead.

---

## 2. Multi-Instance Support & Loop Prevention

PyDivert supports running multiple concurrent instances on the same interface using the Linux kernel's native **TC priority chaining**:

1. **Classifier Chaining**: When multiple handles are opened, their filters are executed in sequence based on their priority.
2. **Dynamic Priorities**: By default, if the priority is set to `0`, PyDivert automatically assigns a unique TC priority to place the new instance after existing ones.
3. **Loop Prevention Mark**:
   To prevent packets injected by PyDivert from being caught recursively by the same or higher priority handles, PyDivert marks injected packets using a socket mark:
   $$\text{SO\_MARK} = \text{PREVENT\_MARK} \mid (\text{priority} \ \& \ \text{0xFFFF})$$
   The BPF program checks this mark. If the classifier priority is higher or equal (lower or equal integer value) than the mark's priority, the BPF program ignores the packet (`TC_ACT_UNSPEC`), allowing lower-priority handles down the chain to capture it if needed.

---

## 3. Asyncio Implementation

Because the underlying BPF ring buffer polling and raw socket sending calls block, PyDivert's asynchronous functions (`recv_async`, `send_async`, `recv_batch_async`, `send_batch_async`) delegate blocking calls to worker threads using `asyncio.to_thread()`:

```python
# Under the hood
async def _recv_async_impl(self, bufsize, timeout):
    return await asyncio.to_thread(self._recv_impl, bufsize, timeout)
```

This ensures the asyncio event loop is not blocked during packet capture and reinjection.

---

## 4. Layer & Flag Translations

WinDivert layers and flags are translated to Linux eBPF equivalents:

| WinDivert Layer | Linux eBPF Implementation | Status / Behavior |
| :--- | :--- | :--- |
| `Layer.NETWORK` | TC Ingress/Egress hooks | **Full support** (Capture, Modify, Drop, Inject). |
| `Layer.FLOW` | TC hooks + Event mapping | **Sniff-only**. Connection events are captured, but packets cannot be blocked. |
| `Layer.SOCKET` | TC hooks + Event mapping | **Sniff-only**. Socket-level metadata is emulated where possible. |
| `Layer.REFLECT` | N/A | **Not supported** on Linux. |

| WinDivert Flag | eBPF Implementation |
| :--- | :--- |
| `Flag.SNIFF` | BPF returns `TC_ACT_OK` after submitting a copy to the ring buffer. |
| `Flag.DROP` | BPF returns `TC_ACT_SHOT` to discard the packet immediately. |
| `Flag.FRAGMENTS` | Supported. BPF logic handles L3 detection for fragmented packets. |
| `Flag.RECV_ONLY` | Disables the raw socket used for re-injection. |
| `Flag.SEND_ONLY` | Disables TC hook attachment; used only for packet injection. |

---

## 5. Elevated Privileges & Capabilities

Interacting with the TC subsystem, loading BPF bytecode, and creating raw packet sockets requires elevated privileges. Your application must be run:
- With `root` privileges (e.g. `sudo python app.py`).
- OR with the specific capabilities: `CAP_NET_ADMIN` (to manipulate TC) and `CAP_BPF` (to load BPF maps and programs).

---

## 6. Linux-Specific Interface Selection

Unlike WinDivert on Windows which captures packets system-wide, the Linux eBPF backend allows you to restrict capture to specific interfaces via the `interfaces` constructor parameter:

```python
import pydivert

# Linux-only: Capture only on interface 'eth0'
with pydivert.Divert("tcp.DstPort == 80", interfaces=["eth0"]) as w:
    for packet in w:
        print(packet)
        w.send(packet)
```
