import subprocess
import os
import sys
import shutil

VMs = ["windows", "linux", "freebsd", "macos"]

def run_cmd(cmd, shell=False):
    print(f"Executing: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    # We want to stream output for the main test commands
    result = subprocess.run(cmd, shell=shell)
    return result

def main():
    if not shutil.which("vagrant"):
        print("Error: vagrant not found in PATH.")
        sys.exit(1)

    # Ensure VMs are up
    print("Starting/Provisioning VMs... (this may take a while)")
    run_cmd(["vagrant", "up"])

    coverage_files = []

    for vm in VMs:
        print(f"\n--- Testing on {vm} ---")
        if vm == "windows":
            # Target 'windows' specifically
            cmd = ["vagrant", "powershell", "windows", "-c", "$env:UV_PROJECT_ENVIRONMENT='C:\\pydivert_venv'; cd C:\\pydivert; uv run pytest --cov=pydivert --cov-report="]
        elif vm == "linux":
            # Disable rx/tx checksumming on lo so modified packets aren't dropped
            run_cmd(["vagrant", "ssh", "linux", "-c", "sudo ethtool -K lo rx off tx off"])
            cmd = ["vagrant", "ssh", "linux", "-c", "cd /home/vagrant/pydivert && echo 'vagrant' | sudo -S /root/.local/bin/uv run pytest --cov=pydivert --cov-report="]
        elif vm == "freebsd":
            run_cmd(["vagrant", "ssh", "freebsd", "-c", "sudo kldload ipdivert || true"])
            cmd = ["vagrant", "ssh", "freebsd", "-c", "cd /vagrant && echo 'vagrant' | sudo -S .venv/bin/pytest --cov=pydivert --cov-report="]
        elif vm == "macos":
            cmd = ["vagrant", "ssh", "macos", "-c", "cd /Users/vagrant/pydivert && uv run pytest --cov=pydivert --cov-report="]
        
        res = run_cmd(cmd)
        
        # Collect coverage file if it exists locally (via synced folder)
        local_cov = f".coverage.{vm}"
        if os.path.exists(".coverage"):
            shutil.move(".coverage", local_cov)
            coverage_files.append(local_cov)
            print(f"Collected coverage for {vm}")
        else:
            print(f"Warning: .coverage file not found for {vm} (check synced folders)")

    if coverage_files:
        print("\nCombining coverage reports...")
        subprocess.run(["uv", "tool", "run", "coverage", "combine"] + coverage_files)
        subprocess.run(["uv", "tool", "run", "coverage", "report", "-m"])
        subprocess.run(["uv", "tool", "run", "coverage", "html"])
        print("Consolidated report generated. See htmlcov/index.html")
    else:
        print("No coverage files collected.")

if __name__ == "__main__":
    main()
