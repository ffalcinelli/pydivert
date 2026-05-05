#!/bin/bash
set -e

export PATH="/usr/local/bin:$PATH"

echo "Compiling eBPF program..."
cd /pydivert
clang -O2 -g -target bpf -I pydivert/bpf -c pydivert/bpf/pydivert.bpf.c -o pydivert/bpf/pydivert.bpf.o

echo "Running tests with coverage..."
export COVERAGE_FILE=.coverage.linux
uv run pytest --cov=pydivert --cov-config=.coveragerc pydivert/tests
