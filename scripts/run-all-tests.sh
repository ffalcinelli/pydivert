#!/bin/bash

# This script executes tests with coverage on both Linux and Windows test runners,
# collects the coverage reports, merges them, and produces an aggregated report on the host.

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

if ! uv run --extra test python -m coverage --version >/dev/null 2>&1; then
    echo "--- Installing coverage tool on host ---"
    uv sync --extra test
fi

echo "--- Starting Linux tests ---"
if [ "${USE_DOCKER:-0}" = "1" ]; then
    if ! ./scripts/test-docker.sh; then
        echo "Warning: Linux tests encountered errors, but attempting to proceed with aggregation."
    fi
else
    if ! python3 scripts/vm.py run linux; then
        echo "Warning: Linux tests encountered errors, but attempting to proceed with aggregation."
    fi
fi

echo "--- Starting Windows tests ---"
if ! python3 scripts/vm.py run windows; then
    echo "Warning: Windows tests encountered errors, but attempting to proceed with aggregation."
fi

echo "--- Aggregating coverage reports ---"
if [ -f .coverage.linux ] || [ -f .coverage.windows ]; then
    uv run --extra test python -m coverage combine

    echo "--- Generating Terminal Report ---"
    uv run --extra test python -m coverage report

    echo "--- Generating HTML Report ---"
    uv run --extra test python -m coverage html

    echo "Done! The aggregated HTML report is available in the 'htmlcov' directory."
else
    echo "Error: No coverage files (.coverage.linux or .coverage.windows) found. Aggregation failed."
    exit 1
fi
