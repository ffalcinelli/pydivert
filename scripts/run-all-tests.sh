#!/bin/bash

# This script executes tests with coverage on both Linux and Windows Vagrant VMs,
# collects the coverage reports, merges them, and produces an aggregated report on the host.

# Ensure we have the coverage tool installed on the host
if ! uv run --extra test python -m coverage --version >/dev/null 2>&1; then
    echo "--- Installing coverage tool on host ---"
    uv sync --extra test
fi

echo "--- Starting Linux tests on Vagrant VM ---"
if ! vagrant ssh linux -c "sudo bash /pydivert/scripts/run-tests-linux.sh"; then
    echo "Warning: Linux tests encountered errors, but attempting to proceed with aggregation."
fi

echo "--- Starting Windows tests on Vagrant VM ---"
if ! vagrant winrm windows -c "powershell -ExecutionPolicy Bypass -File C:\pydivert\scripts\run-tests-windows.ps1"; then
    echo "Warning: Windows tests encountered errors (possibly due to WinRM/PowerShell stderr handling), but attempting to proceed with aggregation."
fi

echo "--- Aggregating coverage reports ---"
# Check if we have any coverage files to combine
if [ -f .coverage.linux ] || [ -f .coverage.windows ]; then
    # Combine the coverage files. 'uv run python -m coverage combine' will look for .coverage.* files by default.
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
