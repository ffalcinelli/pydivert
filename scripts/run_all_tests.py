import argparse
import os
import shutil
import subprocess
import sys
import time

# Define all targets, including 'local' for the host OS
TARGETS = ["local", "windows", "linux", "freebsd", "macos"]


class Tee:
    def __init__(self, filename):
        self.terminal_stdout = sys.stdout
        self.terminal_stderr = sys.stderr
        self.logfile = open(filename, "w", encoding="utf-8")

    def write(self, message):
        self.terminal_stdout.write(message)
        self.logfile.write(message)
        self.logfile.flush()

    def flush(self):
        self.terminal_stdout.flush()
        self.logfile.flush()

    def close(self):
        if self.logfile:
            self.logfile.close()
            self.logfile = None


def run_cmd(cmd, shell=False, check=True, env=None, timeout=None):
    print(f"Executing: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    actual_env = os.environ.copy()
    if env:
        actual_env.update(env)

    try:
        process = subprocess.Popen(
            cmd,
            shell=shell,
            env=actual_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Stream output in real-time
        if process.stdout:
            for line in process.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()

        return_code = process.wait(timeout=timeout)

        if check and return_code != 0:
            print(f"Command failed with exit code {return_code}")
            raise subprocess.CalledProcessError(return_code, cmd)

        # Create a mock result object to maintain compatibility with existing code
        class MockResult:
            def __init__(self, rc):
                self.returncode = rc
        return MockResult(return_code)

    except subprocess.CalledProcessError as e:
        return e
    except subprocess.TimeoutExpired as e:
        print(f"Command timed out after {timeout} seconds")
        process.kill()
        return e
    except Exception as e:
        print(f"An error occurred: {e}")
        return e


def test_target(target):
    print(f"\n--- Testing on {target} ---")

    # Ensure a clean project root for each target
    if os.path.exists(".coverage"):
        os.remove(".coverage")

    target_cov_file = f".coverage.{target}"
    # Remove any existing target-specific coverage file to avoid stale data
    if os.path.exists(target_cov_file):
        os.remove(target_cov_file)

    # Use a specific COVERAGE_FILE for each target to avoid collisions and lost data
    target_env = {"COVERAGE_FILE": ".coverage"}

    if target == "local":
        # Check if pytest-cov is available in the uv environment
        check_cov = subprocess.run(["uv", "run", "python", "-c", "import pytest_cov"], capture_output=True)
        if check_cov.returncode == 0:
            cmd = ["uv", "run", "python", "-m", "pytest", "--timeout=60", "--cov=pydivert", "--cov-report="]
        else:
            # Fallback to coverage run
            cmd = ["uv", "run", "python", "-m", "coverage", "run", "--source=pydivert", "-m", "pytest", "--timeout=60"]
    elif target == "windows":
        run_cmd(["vagrant", "up", "windows"], check=False, timeout=300)
        ps_cmd = (
            "$env:UV_PROJECT_ENVIRONMENT='C:\\pydivert_venv'; "
            "$env:COVERAGE_FILE='C:\\pydivert\\.coverage'; "
            "cd C:\\pydivert; $env:PYTHONWARNINGS='ignore'; "
            "C:\\pydivert_venv\\Scripts\\python.exe -m pytest --timeout=60 --cov=pydivert --cov-report=; "
            "exit $LASTEXITCODE"
        )
        cmd = ["vagrant", "powershell", "windows", "-c", ps_cmd]
    elif target == "linux":
        run_cmd(["vagrant", "up", "linux"], check=False, timeout=300)
        run_cmd(["vagrant", "ssh", "linux", "-c", "sudo ethtool -K lo rx off tx off"], check=False, timeout=60)
        linux_cmd = (
            "cd /home/vagrant/pydivert && "
            "export COVERAGE_FILE=.coverage; "
            "echo 'vagrant' | sudo -S /home/vagrant/pydivert_venv/bin/python -m pytest "
            "--timeout=60 --cov=pydivert --cov-report="
        )
        cmd = ["vagrant", "ssh", "linux", "-c", linux_cmd]
    elif target == "freebsd":
        run_cmd(["vagrant", "up", "freebsd"], check=False, timeout=300)
        run_cmd(["vagrant", "ssh", "freebsd", "-c", "sudo kldload ipdivert || true"], check=False, timeout=60)
        run_cmd(["vagrant", "rsync", "freebsd"], check=False, timeout=60)

        # Ensure dependencies are installed
        pkg_cmd = (
            "sudo -S /home/vagrant/pydivert_venv/bin/pip install pytest "
            "pytest-cov scapy hypothesis mock pytest-asyncio "
            "pytest-timeout lark"
        )
        run_cmd(["vagrant", "ssh", "freebsd", "-c", f"echo 'vagrant' | {pkg_cmd}"], check=False, timeout=300)

        freebsd_cmd = (
            "cd /vagrant; "
            "export COVERAGE_FILE=.coverage; "
            "echo 'vagrant' | sudo -S /home/vagrant/pydivert_venv/bin/python -m pytest "
            "--timeout=60 --cov=pydivert --cov-report="
        )
        cmd = ["vagrant", "ssh", "freebsd", "-c", freebsd_cmd]
    elif target == "macos":
        res = run_cmd(["vagrant", "up", "macos"], check=False, timeout=600)
        if isinstance(res, subprocess.TimeoutExpired) or res.returncode != 0:
            print("Skipping real macOS (VM failed to start or timed out).")
            return None
        macos_cmd = (
            "cd /Users/vagrant/pydivert && "
            "export COVERAGE_FILE=.coverage; "
            "/Users/vagrant/pydivert_venv/bin/python -m pytest --timeout=60 --cov=pydivert --cov-report="
        )
        cmd = ["vagrant", "ssh", "macos", "-c", macos_cmd]
    else:
        return None

    run_cmd(cmd, check=False, env=target_env, timeout=600)

    # Wait for filesystem sync
    time.sleep(5)

    # Priority 1: Check for .coverage in project root
    if os.path.exists(".coverage"):
        shutil.move(".coverage", target_cov_file)
        print(f"Collected coverage for {target} into {target_cov_file}")
        return target_cov_file

    # Priority 2: Check for any .coverage.* file
    for f in os.listdir("."):
        if f.startswith(".coverage") and f != ".coveragerc" and not f.startswith(".coverage."):
             shutil.move(f, target_cov_file)
             print(f"Collected coverage for {target} from {f} into {target_cov_file}")
             return target_cov_file

    print(f"Warning: No coverage data found for {target}")
    return None


def main():
    parser = argparse.ArgumentParser(description="Run pydivert tests on multiple platforms.")
    parser.add_argument("-o", "--output", help="Write stdout and stderr to a file.")
    parser.add_argument("--targets", nargs="+", choices=TARGETS, default=TARGETS, help="Specific targets to test.")
    args = parser.parse_args()

    tee = None
    if args.output:
        print(f"Logging output to {args.output}")
        tee = Tee(args.output)
        sys.stdout = tee
        sys.stderr = tee

    try:
        coverage_files = []

        for target in args.targets:
            cov_file = test_target(target)
            if cov_file:
                coverage_files.append(cov_file)

        if coverage_files:
            # Filter only existing files to avoid 'Couldn't combine from non-existent path'
            existing_files = [f for f in coverage_files if os.path.exists(f)]
            if not existing_files:
                print("No existing coverage files to combine.")
                return

            print(f"\nCombining coverage reports: {existing_files}")
            cov_cmd = ["uv", "run", "python", "-m", "coverage"]
            # Use .coveragerc to map paths from different VMs to local paths
            run_cmd(cov_cmd + ["combine", "--rcfile=.coveragerc"] + existing_files, check=False)
            run_cmd(cov_cmd + ["report", "-m"], check=False)
            run_cmd(cov_cmd + ["html"], check=False)
            print("Consolidated report generated. See htmlcov/index.html")
        else:
            print("No coverage files collected.")
    finally:
        if tee:
            sys.stdout = tee.terminal_stdout
            sys.stderr = tee.terminal_stderr
            tee.close()


if __name__ == "__main__":
    main()
"__main__":
    main()
