# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Copyright (C) 2026  Fabio Falcinelli, Maximilian Hils
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of either:
#
# 1) The GNU Lesser General Public License as published by the Free
#    Software Foundation, either version 3 of the License, or (at your
#    option) any later version.
#
# 2) The GNU General Public License as published by the Free Software
#    Foundation, either version 2 of the License, or (at your option)
#    any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License and the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# and the GNU General Public License along with this program.  If not,
# see <https://www.gnu.org/licenses/>.

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
        "cd C:/pydivert; "
        "uv run pytest --cov=pydivert --cov-report=xml"
    )
    return run_cmd(["vagrant", "powershell", "windows", "-c", cmd])


def run_tests_on_linux():
    print("=== Running tests on Linux VM ===")
    # Sync first to ensure dependencies
    run_cmd(["vagrant", "ssh", "linux", "-c", "cd /home/vagrant/pydivert && sudo uv sync --extra test --extra linux"])
    cmd = "cd /home/vagrant/pydivert && sudo uv run pytest --cov=pydivert --cov-append --cov-report=xml"
    return run_cmd(["vagrant", "ssh", "linux", "-c", cmd])


def run_tests_on_macos():
    print("=== Running tests on macOS ===")
    # This assumes we are on a macos host or using a macos runner
    cmd = [
        "uv",
        "run",
        "pytest",
        "--cov=pydivert",
        "--cov-append",
        "--cov-report=xml",
        "pydivert/tests/test_macos_mock.py",
    ]
    return run_cmd(cmd)


def cleanup_vagrant():
    print("=== Cleaning up Vagrant VMs ===")
    run_cmd(["vagrant", "halt"])


def main():
    # Setup logging to file and stdout
    log_file = "test_run.log"
    tee = Tee(log_file)
    original_stdout = sys.stdout
    sys.stdout = tee

    start_time = time.time()
    results = {}

    try:
        # Start VMs
        print("=== Starting Vagrant VMs ===")
        run_cmd(["vagrant", "up", "windows", "linux"])

        # Run tests
        results["windows"] = run_tests_on_windows()
        results["linux"] = run_tests_on_linux()

        # macOS tests (usually mocked if not on macOS)
        results["macos"] = run_tests_on_macos()

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


if __name__ == "__main__":
    main()
