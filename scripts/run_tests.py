#!/usr/bin/env python3
"""
PyDivert Unified Test Orchestrator
Runs tests on Linux (Docker or QEMU/KVM VM) and Windows (QEMU/KVM VM), collects coverage, and merges results.
"""

import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
COVERAGE_FILE_LINUX = PROJECT_ROOT / ".coverage.linux"
COVERAGE_FILE_WINDOWS = PROJECT_ROOT / ".coverage.windows"


def run_command(cmd, cwd=None, check=True):
    """Utility to run shell commands."""
    print(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=cwd, check=check)


def ensure_host_dependencies():
    """Ensures coverage tool is installed on the host."""
    print("--- Ensuring host dependencies ---")
    run_command(["uv", "sync", "--extra", "test"], cwd=PROJECT_ROOT)


def run_linux_tests(use_docker: bool = False):
    """Runs tests on Linux via Docker or the QEMU/KVM VM."""
    mode = "Docker" if use_docker else "QEMU/KVM VM"
    print(f"--- Running Linux tests (eBPF via {mode}) ---")
    try:
        if use_docker:
            run_command(["bash", str(PROJECT_ROOT / "scripts" / "test-docker.sh")], cwd=PROJECT_ROOT)
        else:
            run_command([sys.executable, str(PROJECT_ROOT / "scripts" / "vm.py"), "run", "linux"], cwd=PROJECT_ROOT)
    except subprocess.CalledProcessError:
        print("Warning: Linux tests encountered errors.")
        return False
    return True


def run_windows_tests():
    """Runs tests on the Windows QEMU/KVM VM."""
    print("--- Running Windows tests (WinDivert via QEMU/KVM VM) ---")
    try:
        run_command([sys.executable, str(PROJECT_ROOT / "scripts" / "vm.py"), "run", "windows"], cwd=PROJECT_ROOT)
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

    run_command(["uv", "run", "--extra", "test", "python", "-m", "coverage", "combine"], cwd=PROJECT_ROOT)
    run_command(["uv", "run", "--extra", "test", "python", "-m", "coverage", "report"], cwd=PROJECT_ROOT)
    run_command(["uv", "run", "--extra", "test", "python", "-m", "coverage", "html"], cwd=PROJECT_ROOT)

    print(f"Done! Aggregated HTML report available in {PROJECT_ROOT / 'htmlcov'}")
    return True


def main():
    parser = argparse.ArgumentParser(description="PyDivert Unified Test Orchestrator")
    parser.add_argument("--linux", action="store_true", help="Run Linux tests only")
    parser.add_argument("--windows", action="store_true", help="Run Windows tests only")
    parser.add_argument("--docker", action="store_true", help="Use privileged Docker instead of QEMU for Linux")
    parser.add_argument("--no-agg", action="store_true", help="Do not aggregate coverage")

    args = parser.parse_args()

    ensure_host_dependencies()

    success = True
    if args.linux:
        success = run_linux_tests(use_docker=args.docker) and success
    elif args.windows:
        success = run_windows_tests() and success
    else:
        success_linux = run_linux_tests(use_docker=args.docker)
        success_windows = run_windows_tests()
        success = success_linux and success_windows

    if not args.no_agg:
        aggregate_coverage()

    if not success:
        print("One or more test suites failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
