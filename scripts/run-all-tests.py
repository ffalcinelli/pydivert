import os
import shutil
import subprocess

# Define all targets, including 'local' for the host OS
TARGETS = ["local", "windows", "linux", "freebsd", "macos"]


def run_cmd(cmd, shell=False, check=True):
    print(f"Executing: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    try:
        result = subprocess.run(cmd, shell=shell, check=check)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Command failed with exit code {e.returncode}")
        return e


def test_target(target):
    print(f"\n--- Testing on {target} ---")
    if target == "local":
        cmd = ["uv", "run", "python", "-m", "pytest", "--cov=pydivert", "--cov-report="]
    elif target == "windows":
        run_cmd(["vagrant", "up", "windows"], check=False)
        ps_cmd = (
            "$env:UV_PROJECT_ENVIRONMENT='C:\\pydivert_venv'; "
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
            "echo 'vagrant' | sudo -S /home/vagrant/pydivert_venv/bin/python -m pytest "
            "--cov=pydivert --cov-report="
        )
        cmd = ["vagrant", "ssh", "linux", "-c", linux_cmd]
    elif target == "freebsd":
        run_cmd(["vagrant", "up", "freebsd"], check=False)
        run_cmd(["vagrant", "ssh", "freebsd", "-c", "sudo kldload ipdivert || true"], check=False)
        run_cmd(["vagrant", "rsync", "freebsd"], check=False)
        freebsd_cmd = (
            "cd /vagrant && echo 'vagrant' | sudo -S /home/vagrant/pydivert_venv/bin/python -m pytest "
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
            "/Users/vagrant/pydivert_venv/bin/python -m pytest --cov=pydivert --cov-report="
        )
        cmd = ["vagrant", "ssh", "macos", "-c", macos_cmd]
    else:
        return None

    res = run_cmd(cmd, check=False)
    if res.returncode != 0:
        print(f"Tests failed on {target}, but attempting to collect partial coverage.")

    local_cov = f".coverage.{target}"
    if os.path.exists(".coverage"):
        shutil.move(".coverage", local_cov)
        print(f"Collected coverage for {target}")
        return local_cov
    else:
        print(f"Warning: .coverage file not found for {target}")
        return None


def main():
    coverage_files = []

    for target in TARGETS:
        cov_file = test_target(target)
        if cov_file:
            coverage_files.append(cov_file)

    if coverage_files:
        print("\nCombining coverage reports...")
        cov_cmd = ["uv", "run", "coverage"] if shutil.which("uv") else ["coverage"]
        run_cmd(cov_cmd + ["combine"] + coverage_files, check=False)
        run_cmd(cov_cmd + ["report", "-m"], check=False)
        run_cmd(cov_cmd + ["html"], check=False)
        print("Consolidated report generated. See htmlcov/index.html")
    else:
        print("No coverage files collected.")


if __name__ == "__main__":
    main()
