# PyDivert

PyDivert is a cross-platform Python (3.10+) binding for capturing, modifying, dropping and injecting network
packets. Its backends are WinDivert on Windows and libebpfdivert (eBPFDivert) on Linux. Both share the
WinDivert filter language, layers, flags and packet metadata, so behavior must stay identical across
platforms.

## Commands

```bash
uv sync --extra test                                       # dev env (editable build tries to fetch host binaries)
python scripts/fetch_binaries.py                           # fetch the pinned WinDivert / libebpfdivert binaries
uv run --extra lint ruff check pydivert                    # lint
uv run --extra lint ruff format --check pydivert           # format check (line length 120)
uv run --extra typecheck --extra test ty check pydivert    # type check
uv run --extra docs python docs/build.py                   # pdoc site (README + docs/*.md are included)
uv run pre-commit run --all-files                          # ruff, ruff-format, ty, whitespace hooks
```

Tests touch the real network stack and need root on Linux or Administrator on Windows. Run them in the Vagrant
VMs, one VM at a time:

```bash
python scripts/run_tests.py --linux --up                   # or --windows; with neither it runs both
                                                           # and merges coverage into htmlcov/
vagrant up linux && vagrant provision linux --provision-with test-linux; vagrant destroy -f linux
vagrant up windows && vagrant provision windows --provision-with test-windows
```

Run a single test on a Linux machine as root:
`sudo -E .venv/bin/python -m pytest pydivert/tests/test_packet.py -k test_name`. Pytest settings live in
`pyproject.toml`: a 60 s timeout and `asyncio_mode = auto`.

To use a local eBPFDivert build:
- **Copy it in:**
  `PYDIVERT_EBPFDIVERT_LOCAL=../ebpfdivert/libebpfdivert.so python scripts/fetch_binaries.py`.
- **Point at it at runtime:** `PYDIVERT_EBPFDIVERT_LIB=/path/to/libebpfdivert.so`.

## Architecture

- **`core.Divert`** is the public facade. It delegates to `windivert.WinDivert` on Windows, or `ebpf.EBPFDivert`
  on Linux. Both subclass `base.BaseDivert`, which provides sync (`recv`/`send`) and async
  (`recv_async`/`send_async`) operation.
- **`ebpf.EBPFDivert`** is a thin ctypes shim that mirrors `WinDivert` call for call. `bpf/__init__.py` finds and
  loads `libebpfdivert.so` and declares its structs. Linux-only kwargs: `interfaces`, `ring_bytes`.
- **`windivert_dll/`** holds the ctypes declarations (`structs.py`) plus the downloaded `WinDivert64.dll` /
  `.sys`. `service.py` manages the Windows driver service.
- **`packet/`** holds `Packet` (lazy header parsing, metadata, checksums), the ip/tcp/udp/icmp headers, and
  `PacketBuilder`.
- **`consts.py`** holds the enums that mirror WinDivert constants.
- **Native binaries:**
  - **Pins.** Versions are set in `[tool.pydivert.binaries]` in `pyproject.toml`.
  - **Fetching.** `scripts/fetch_binaries.py` downloads them to git-ignored locations.
  - **Wheels.** `hatch_build.py` fetches the target's binaries at wheel build time and tags the wheel per
    platform. To cross-build, set `PYDIVERT_TARGET=win_amd64|manylinux_2_28_x86_64|manylinux_2_28_aarch64`;
    `SKIP_FETCH_BINARIES=1` skips the fetch.
- The Linux backend is documented in `docs/LINUX_BACKEND.md`, the filter language in `docs/FILTER_LANGUAGE.md`.

## Rules

- **Parity.** A behavior change must hold on both backends. Prefer fixing a Linux discrepancy in eBPFDivert
  rather than special-casing it in Python.
- **Types.** `ty` is configured with `python-platform = "win32"`. Guard Linux-only code paths so they still
  type-check.
- **README.** The README's code examples are presented as runnable. Keep them correct when the API changes.
- **Wheel contents.** The distributed wheel must include the `pydivert/tests` package, for post-install
  verification on target machines.
- **CI/CD and supply chain:**
  - All GitHub Actions in `.github/workflows/` are pinned to 40-character commit SHAs with a `# vX.Y.Z`
    comment. Mutable tags such as `@v6` are forbidden, and `ffalcinelli/pinner` (`.pinner.toml`) enforces it.
  - Actions must use the Node 24 runtime, or the current stable one.
  - CI (`ci.yml`) and release (`release.yml`) stay in separate workflow files.
- **License.** LGPL-3.0-or-later OR GPL-2.0-or-later. New source files get the SPDX header used in the package.
