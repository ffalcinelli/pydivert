#!/bin/bash
set -e

export PATH="/usr/local/bin:$PATH"

echo "Fetching eBPF driver..."
cd /pydivert
python3 scripts/fetch_ebpfdivert.py

echo "Ensuring dependencies are up to date..."
uv sync --extra test

echo "Running tests with coverage..."
export COVERAGE_FILE=.coverage.linux
uv run pytest --cov=pydivert --cov-config=.coveragerc pydivert/tests
