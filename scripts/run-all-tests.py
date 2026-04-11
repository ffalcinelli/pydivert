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

def main():
    coverage_files = []

    for target in TARGETS:
        print(f"\n--- Testing on {target} ---")
        if target == "local":
            # Run tests on the host OS
            cmd = ["uv", "run", "python", "-m", "pytest", "--cov=pydivert", "--cov-report="]
        elif target == "windows":
            run_cmd(["vagrant", "up", "windows"], check=False)
            # Use PowerShell to execute pytest and explicitly exit with its exit code.
            # We also try to suppress Scapy's warning by setting log level if possible, 
            # or just ignore it.
            cmd = ["vagrant", "powershell", "windows", "-c", "$env:UV_PROJECT_ENVIRONMENT='C:\\pydivert_venv'; cd C:\\pydivert; $env:PYTHONWARNINGS='ignore'; C:\\pydivert_venv\\Scripts\\python.exe -m pytest --cov=pydivert --cov-report=; exit $LASTEXITCODE"]
        elif target == "linux":
            run_cmd(["vagrant", "up", "linux"], check=False)
            run_cmd(["vagrant", "ssh", "linux", "-c", "sudo ethtool -K lo rx off tx off"], check=False)
            cmd = ["vagrant", "ssh", "linux", "-c", "cd /home/vagrant/pydivert && echo 'vagrant' | sudo -S /home/vagrant/pydivert_venv/bin/python -m pytest --cov=pydivert --cov-report="]
        elif target == "freebsd":
            run_cmd(["vagrant", "up", "freebsd"], check=False)
            run_cmd(["vagrant", "ssh", "freebsd", "-c", "sudo kldload ipdivert || true"], check=False)
            run_cmd(["vagrant", "rsync", "freebsd"], check=False)
            cmd = ["vagrant", "ssh", "freebsd", "-c", "cd /vagrant && echo 'vagrant' | sudo -S /home/vagrant/pydivert_venv/bin/python -m pytest --cov=pydivert --cov-report="]
        elif target == "macos":
            # Best effort for macOS
            res = run_cmd(["vagrant", "up", "macos"], check=False)
            if res.returncode != 0:
                print("Skipping real macOS (VM failed to start).")
                continue
            cmd = ["vagrant", "ssh", "macos", "-c", "cd /Users/vagrant/pydivert && /Users/vagrant/pydivert_venv/bin/python -m pytest --cov=pydivert --cov-report="]

        res = run_cmd(cmd, check=False)
        if res.returncode != 0:
            print(f"Tests failed on {target}, but attempting to collect partial coverage.")

        local_cov = f".coverage.{target}"
        if os.path.exists(".coverage"):
            shutil.move(".coverage", local_cov)
            coverage_files.append(local_cov)
            print(f"Collected coverage for {target}")
        else:
            print(f"Warning: .coverage file not found for {target}")

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
