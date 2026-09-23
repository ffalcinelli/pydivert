# Linux Backend Guide

On Linux, `pydivert.Divert` is backed by [eBPFDivert](https://github.com/ffalcinelli/ebpfdivert): `libebpfdivert.so`,
a C library that implements the WinDivert API with eBPF. The wheel bundles it, and it is self-contained: the BPF
programs and libbpf are built in. `pydivert.ebpf.EBPFDivert` is a thin ctypes shim over it, mirroring
`pydivert.windivert.WinDivert` call for call. As a result, filters, layers, flags, parameters and packet metadata
behave as on Windows.

---

## 1. Requirements

- Linux **5.10 or newer** with BTF (`/sys/kernel/btf/vmlinux`), which is the default on current distributions.
  It is tested on 5.15 and 6.8.
- **cgroup v2**, for the FLOW and SOCKET layers.
- x86_64 or aarch64, glibc 2.28+.
- Root, or the capabilities `CAP_BPF`, `CAP_NET_ADMIN` and `CAP_NET_RAW`.

Nothing else needs to be installed (no libbpf, no kernel headers). Offloads (GSO/GRO/TSO) can stay enabled.

---

## 2. How it works

- **Filters.** They are compiled by WinDivert's own filter compiler, which is built into the library.
  - The library lowers them to eBPF rules evaluated in the kernel, on TC ingress/egress of every interface.
  - If a filter cannot be expressed exactly in the kernel (for example `tcp.PayloadLength > 100`), the kernel
    captures a superset. The library then evaluates the exact filter and silently re-injects the packets that
    don't match.
  - Either way, `recv()` returns exactly what WinDivert would return. `Packet.matches()` uses the same evaluator.
- **Loopback.** Loopback traffic is reported once, as outbound with `is_loopback` set, like on Windows.
- **Priorities.** Handles chain by priority. A re-injected packet is seen only by lower-priority handles, with
  `is_impostor` set. With `priority=0`, a handle is placed after the ones already open.
- **Large packets.** Packets of up to 64 KB (GRO/TSO aggregates) are captured whole. Allow for this with
  `bufsize` if you call `recv()` with a small buffer (the default buffer is large enough).
- **Crashes.** If a process dies without closing its handles, the kernel programs stop diverting within
  3 seconds, and they are removed by the next `Divert()` or by `Divert.unregister()`. A crashed script never
  blackholes traffic.
- **asyncio.** `recv_async()` waits on the library's event descriptor with `loop.add_reader()`, so no thread is
  used.

---

## 3. Layers and flags

| Layer | Linux implementation | Notes |
| :--- | :--- | :--- |
| `Layer.NETWORK` | TC hooks | Full support: capture, modify, drop, inject. |
| `Layer.NETWORK_FORWARD` | TC hooks | Routed packets only (IP forwarding enabled). |
| `Layer.FLOW` | cgroup/sockops programs | TCP and UDP flows. `Flag.SNIFF \| Flag.RECV_ONLY` is required, as on Windows. |
| `Layer.SOCKET` | cgroup programs | BIND, CONNECT, LISTEN, ACCEPT, CLOSE, with `process_id`. `Flag.RECV_ONLY` is required. |
| `Layer.REFLECT` | handle registry | Divert handles of all processes. `Flag.SNIFF \| Flag.RECV_ONLY` is required. |

| Flag | Behaviour |
| :--- | :--- |
| `Flag.SNIFF` | Packets continue; you receive copies. |
| `Flag.DROP` | Matching packets are dropped in the kernel. |
| `Flag.FRAGMENTS` | Inbound IP fragments are also captured (they are skipped by default, as on Windows). |
| `Flag.RECV_ONLY` / `Flag.SEND_ONLY` | As on Windows. |
| `Flag.NO_INSTALL` | Accepted; nothing to install on Linux. |

The `Param.QUEUE_LEN`, `Param.QUEUE_TIME` and `Param.QUEUE_SIZE` parameters, `shutdown()`, and `stats()`
are all supported.

### Differences from Windows

- **SOCKET blocking.** A SOCKET handle without `Flag.SNIFF` blocks the matching BIND and CONNECT calls, and the
  process gets `EPERM`. Linux cannot block LISTEN and ACCEPT. A filter that could match them, or that uses
  fields other than event, protocol, local/remote address and port, and `processId`, raises
  `NotImplementedError` unless `Flag.SNIFF` is set.
- **Timestamps** are `CLOCK_MONOTONIC` nanoseconds.
- **`sub_interface`** is always 0.

---

## 4. Linux-only options

`Divert` accepts two extra keyword arguments on Linux:

```python
import pydivert

# Capture only on eth0 (loopback is always included)
with pydivert.Divert("tcp.DstPort == 80", interfaces=["eth0"], ring_bytes=16 << 20) as w:
    for packet in w:
        w.send(packet)
```

- `interfaces`: the list of interface names to attach to. The default is all interfaces.
- `ring_bytes`: the size of the kernel ring buffer. The default is 8 MB.

---

## 5. Troubleshooting

- **`PermissionError`**: run as root or grant the capabilities listed above.
- **`NotImplementedError` for FLOW/SOCKET**: cgroup v2 is not mounted (`mount | grep cgroup2`).
- **A different library build**: set `PYDIVERT_EBPFDIVERT_LIB=/path/to/libebpfdivert.so`.
- **Programs left behind by killed processes**: `pydivert.Divert.unregister()` removes them. They already pass all
  traffic.
