#!/bin/bash
set -e

export PATH="/usr/local/bin:$PATH"
export SKIP_FETCH_BINARIES=1

echo "Applying network sysctl configurations for loopback injection..."
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.lo.rp_filter=0
sudo sysctl -w net.ipv4.conf.all.route_localnet=1
sudo sysctl -w net.ipv4.conf.lo.route_localnet=1
sudo sysctl -w net.ipv4.conf.all.accept_local=1
sudo sysctl -w net.ipv4.conf.lo.accept_local=1

echo "Fetching pre-built binaries..."
cd /pydivert
python3 scripts/fetch_binaries.py

echo "Ensuring dependencies are up to date..."
uv sync --extra test

echo "Running tests with coverage..."
export COVERAGE_FILE=.coverage.linux
sudo -E .venv/bin/python -m pytest --cov=pydivert --cov-config=.coveragerc pydivert/tests
