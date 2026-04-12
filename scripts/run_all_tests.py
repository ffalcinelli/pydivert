import os
import shutil
import subprocess
import time

# Define all targets, including 'local' for the host OS
TARGETS = ["local", "windows", "linux", "freebsd", "macos"]


def run_cmd(cmd, shell=False, check=True, env=None):
    print(f"Executing: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    try:
        actual_env = os.environ.copy()
        if env:
            actual_env.update(env)
        result = subprocess.run(cmd, shell=shell, check=check, env=actual_env)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Command failed with exit code {e.returncode}")
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
        # Standard local run
        cmd = ["uv", "run", "python", "-m", "pytest", "--cov=pydivert", "--cov-report="]
    elif target == "windows":
        run_cmd(["vagrant", "up", "windows"], check=False)
        ps_cmd = (
            "$env:UV_PROJECT_ENVIRONMENT='C:\\pydivert_venv'; "
            "$env:COVERAGE_FILE='C:\\pydivert\\.coverage'; "
            "cd C:\\pydivert; $env:PYTHONWARNINGS='ignore'; "
            "C:\\pydivert_venv\\Scripts\\python.exe -m pytest --cov=pydivert --cov-report=; "
            "exit $LASTEXITCODE"
        )
        cmd = ["vagrant", "powershell", "windows", "-c", ps_cmd]
    elif target == "linux":
        run_cmd(["vagrant", "up", "linux"], check=False)
        run_cmd(["vagrant", "ssh", "linux", "-c", "sudo ethtool -K lo rx off tx off"], check=False)
        linux_cmd = (
            "cd /home/vagrant/pydivert && "
            "export COVERAGE_FILE=.coverage; "
            "echo 'vagrant' | sudo -S /home/vagrant/pydivert_venv/bin/python -m pytest "
            "--cov=pydivert --cov-report="
        )
        cmd = ["vagrant", "ssh", "linux", "-c", linux_cmd]
    elif target == "freebsd":
        run_cmd(["vagrant", "up", "freebsd"], check=False)
        run_cmd(["vagrant", "ssh", "freebsd", "-c", "sudo kldload ipdivert || true"], check=False)
        run_cmd(["vagrant", "rsync", "freebsd"], check=False)
        
        # Ensure dependencies are installed
        pkg_cmd = "sudo -S /home/vagrant/pydivert_venv/bin/pip install pytest pytest-cov scapy hypothesis mock pytest-asyncio pytest-timeout lark"
        run_cmd(["vagrant", "ssh", "freebsd", "-c", f"echo 'vagrant' | {pkg_cmd}"], check=False)

        freebsd_cmd = (
            "cd /vagrant; "
            "export COVERAGE_FILE=.coverage; "
            "echo 'vagrant' | sudo -S /home/vagrant/pydivert_venv/bin/python -m pytest "
            "--cov=pydivert --cov-report="
        )
        cmd = ["vagrant", "ssh", "freebsd", "-c", freebsd_cmd]
    elif target == "macos":
        res = run_cmd(["vagrant", "up", "macos"], check=False)
        if res.returncode != 0:
            print("Skipping real macOS (VM failed to start).")
            return None
        macos_cmd = (
            "cd /Users/vagrant/pydivert && "
            "export COVERAGE_FILE=.coverage; "
            "/Users/vagrant/pydivert_venv/bin/python -m pytest --cov=pydivert --cov-report="
        )
        cmd = ["vagrant", "ssh", "macos", "-c", macos_cmd]
    else:
        return None

    run_cmd(cmd, check=False, env=target_env)
    
    # Wait for filesystem sync
    time.sleep(2)
    
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
    coverage_files = []

    for target in TARGETS:
        cov_file = test_target(target)
        if cov_file:
            coverage_files.append(cov_file)

    if coverage_files:
        print(f"\nCombining coverage reports: {coverage_files}")
        cov_cmd = ["uv", "run", "python", "-m", "coverage"]
        # Use --data-file to be explicit
        run_cmd(cov_cmd + ["combine"] + coverage_files, check=False)
        run_cmd(cov_cmd + ["report", "-m"], check=False)
        run_cmd(cov_cmd + ["html"], check=False)
        print("Consolidated report generated. See htmlcov/index.html")
    else:
        print("No coverage files collected.")


if __name__ == "__main__":
    main()
