#!/bin/bash
set -e

export PATH="/usr/local/bin:$PATH"

echo "Fetching pre-built binaries..."
cd /pydivert
python3 scripts/fetch_binaries.py

echo "Ensuring dependencies are up to date..."
uv sync --extra test

echo "Running tests with coverage..."
export COVERAGE_FILE=.coverage.linux
uv run pytest --cov=pydivert --cov-config=.coveragerc pydivert/tests
