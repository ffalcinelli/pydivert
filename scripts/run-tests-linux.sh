#!/bin/bash
set -e

export PATH="/usr/local/bin:$PATH"
# Keep the container/VM virtualenv out of the workspace (the host has its own .venv).
export UV_PROJECT_ENVIRONMENT="${UV_PROJECT_ENVIRONMENT:-/opt/pydivert-venv}"
REPO_DIR="${PYDIVERT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$REPO_DIR"

# libebpfdivert.so is self-contained (no libbpf, no sysctl tweaks needed).
# Use an already present library (e.g. a local ebpfdivert build copied into
# pydivert/bpf/), otherwise fetch the pinned release.
if [ ! -f pydivert/bpf/libebpfdivert.so ]; then
    echo "Fetching pre-built binaries..."
    python3 scripts/fetch_binaries.py
fi

echo "Ensuring dependencies are up to date..."
SKIP_FETCH_BINARIES=1 uv sync --extra test

echo "Running tests with coverage..."
export COVERAGE_FILE=.coverage.linux
if [ "$EUID" -eq 0 ]; then
    "$UV_PROJECT_ENVIRONMENT/bin/python" -m pytest --cov=pydivert --cov-config=.coveragerc pydivert/tests
else
    sudo -E "$UV_PROJECT_ENVIRONMENT/bin/python" -m pytest --cov=pydivert --cov-config=.coveragerc pydivert/tests
fi
