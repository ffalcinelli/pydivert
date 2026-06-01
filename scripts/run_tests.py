#!/usr/bin/env python3
"""
PyDivert Unified Test Orchestrator
Runs tests on Linux and Windows Vagrant VMs, collects coverage, and merges results.
"""

import argparse
import subprocess
import sys
from pathlib import Path

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
COVERAGE_FILE_LINUX = PROJECT_ROOT / ".coverage.linux"
COVERAGE_FILE_WINDOWS = PROJECT_ROOT / ".coverage.windows"
COVERAGE_FILE_COMBINED = PROJECT_ROOT / ".coverage"


def run_command(cmd, cwd=None, shell=False, check=True):
    """Utility to run shell commands."""
    print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, cwd=cwd, shell=shell, check=check)


def ensure_host_dependencies():
    """Ensures coverage tool is installed on the host."""
    print("--- Ensuring host dependencies ---")
    run_command(["uv", "sync", "--extra", "test"], cwd=PROJECT_ROOT)


def run_linux_tests():
    """Runs tests on the Linux Vagrant VM."""
    print("--- Running Linux tests (eBPF) ---")
    try:
        run_command(
            ["vagrant", "ssh", "linux", "-c", "sudo bash /pydivert/scripts/run-tests-linux.sh"], cwd=PROJECT_ROOT
        )
    except subprocess.CalledProcessError:
        print("Warning: Linux tests encountered errors.")
        return False
    return True


def run_windows_tests():
    """Runs tests on the Windows Vagrant VM."""
    print("--- Running Windows tests (WinDivert) ---")
    try:
        run_command(
            [
                "vagrant",
                "winrm",
                "windows",
                "-c",
                "powershell -ExecutionPolicy Bypass -File C:\\pydivert\\scripts\\run-tests-windows.ps1",
            ],
            cwd=PROJECT_ROOT,
        )
    except subprocess.CalledProcessError:
        print("Warning: Windows tests encountered errors.")
        return False
    return True


def aggregate_coverage():
    """Combines coverage reports from different platforms."""
    print("--- Aggregating coverage reports ---")
    if not COVERAGE_FILE_LINUX.exists() and not COVERAGE_FILE_WINDOWS.exists():
        print("Error: No coverage files found to aggregate.")
        return False

    # Combine coverage files
    run_command(["uv", "run", "--extra", "test", "python", "-m", "coverage", "combine"], cwd=PROJECT_ROOT)

    # Generate reports
    run_command(["uv", "run", "--extra", "test", "python", "-m", "coverage", "report"], cwd=PROJECT_ROOT)
    run_command(["uv", "run", "--extra", "test", "python", "-m", "coverage", "html"], cwd=PROJECT_ROOT)

    print(f"Done! Aggregated HTML report available in {PROJECT_ROOT / 'htmlcov'}")
    return True


def main():
    parser = argparse.ArgumentParser(description="PyDivert Unified Test Orchestrator")
    parser.add_argument("--linux", action="store_true", help="Run Linux tests only")
    parser.add_argument("--windows", action="store_true", help="Run Windows tests only")
    parser.add_argument("--no-agg", action="store_true", help="Do not aggregate coverage")
    parser.add_argument("--up", action="store_true", help="Ensure VMs are up before running tests")

    args = parser.parse_args()

    if args.up:
        print("--- Ensuring Vagrant VMs are up ---")
        run_command(["vagrant", "up"], cwd=PROJECT_ROOT)

    ensure_host_dependencies()

    success = True
    if args.linux:
        success = run_linux_tests() and success
    elif args.windows:
        success = run_windows_tests() and success
    else:
        # Run both
        success_linux = run_linux_tests()
        success_windows = run_windows_tests()
        success = success_linux and success_windows

    if not args.no_agg:
        aggregate_coverage()

    if not success:
        print("One or more test suites failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
