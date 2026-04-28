# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
import os
import subprocess
import sys
import time


def run_cmd(cmd, shell=False, check=True, env=None, timeout=None):
    """Run a shell command and stream its output."""
    print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    try:
        process = subprocess.Popen(
            cmd,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )

        # Stream output in real-time
        if process.stdout:
            for line in process.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()

        return_code = process.wait(timeout=timeout)

        if check and return_code != 0:
            raise subprocess.CalledProcessError(return_code, cmd)
        return return_code
    except Exception as e:
        print(f"Error running command: {e}")
        if check:
            raise
        return -1


class Tee:
    def __init__(self, filename):
        self.file = open(filename, "w")
        self.stdout = sys.stdout

    def write(self, data):
        self.file.write(data)
        self.stdout.write(data)

    def flush(self):
        self.file.flush()
        self.stdout.flush()

    def close(self):
        self.file.close()


def run_tests_on_windows():
    print("=== Running tests on Windows VM ===")
    cmd = (
        '$env:UV_PROJECT_ENVIRONMENT="C:/pydivert_venv"; '
        '$env:COVERAGE_FILE=".coverage.windows"; '
        "cd C:/pydivert; "
        "uv run --quiet pytest --cov=pydivert; "
        "exit $LASTEXITCODE"
    )
    return run_cmd(["vagrant", "powershell", "windows", "-c", cmd])


def run_tests_on_linux():
    print("=== Running tests on Linux VM ===")
    # Sync first to ensure dependencies
    run_cmd(
        [
            "vagrant",
            "ssh",
            "linux",
            "-c",
            "cd /home/vagrant/pydivert && sudo uv sync --quiet --extra test --extra linux",
        ]
    )
    cmd = (
        "cd /home/vagrant/pydivert && "
        'export COVERAGE_FILE=".coverage.linux" && '
        "sudo -E uv run --quiet pytest --cov=pydivert"
    )
    return run_cmd(["vagrant", "ssh", "linux", "-c", cmd])


def run_tests_on_macos():
    print("=== Running tests on macOS (Local Mock) ===")
    env = os.environ.copy()
    env["COVERAGE_FILE"] = ".coverage.macos"
    cmd = [
        "uv",
        "run",
        "pytest",
        "--cov=pydivert",
        "pydivert/tests/test_macos_mock.py",
    ]
    return run_cmd(cmd, env=env)


def cleanup_coverage():
    print("=== Cleaning up old coverage data ===")
    for f in os.listdir("."):
        if f.startswith(".coverage"):
            os.remove(f)


def combine_coverage():
    print("=== Combining coverage data ===")
    run_cmd(["uv", "run", "coverage", "combine"])
    run_cmd(["uv", "run", "coverage", "xml"])
    run_cmd(["uv", "run", "coverage", "html"])
    print("=== Coverage report generated in htmlcov/index.html ===")


def main():
    # Setup logging to file and stdout
    log_file = "test_run.log"
    tee = Tee(log_file)
    original_stdout = sys.stdout
    sys.stdout = tee

    start_time = time.time()
    results = {}

    try:
        cleanup_coverage()

        # Start VMs
        print("=== Starting Vagrant VMs ===")
        run_cmd(["vagrant", "up", "windows", "linux"])

        # Run tests
        results["windows"] = run_tests_on_windows()
        results["linux"] = run_tests_on_linux()
        results["macos"] = run_tests_on_macos()

        combine_coverage()

    except KeyboardInterrupt:
        print("\nTest run interrupted by user.")
    except Exception as e:
        print(f"\nAn error occurred during test run: {e}")
    finally:
        duration = time.time() - start_time
        print("\n" + "=" * 40)
        print(f"Test Run Summary (Duration: {duration:.2f}s)")
        print("=" * 40)
        for platform, rc in results.items():
            status = "PASSED" if rc == 0 else "FAILED"
            print(f"{platform:10}: {status} (rc={rc})")
        print("=" * 40)

        # Restore stdout
        sys.stdout = original_stdout
        tee.close()

    # Exit with non-zero if any platform failed
    if any(rc != 0 for rc in results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
