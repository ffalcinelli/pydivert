import os
import shutil
import subprocess
import sys

VMs = ["windows", "linux", "freebsd"] # macos is often too slow/flaky for regular local test runs

def run_cmd(cmd, shell=False):
    print(f"Executing: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    result = subprocess.run(cmd, shell=shell)
    return result

def main():
    if not shutil.which("vagrant"):
        print("Error: vagrant not found in PATH.")
        sys.exit(1)

    print("Starting/Provisioning VMs... (this may take a while)")
    run_cmd(["vagrant", "up"])

    coverage_files = []

    for vm in VMs:
        print(f"\n--- Testing on {vm} ---")
        if vm == "windows":
            # Command specifically for windows: use local venv to avoid shared folder issues
            cmd = ["vagrant", "powershell", "windows", "-c", "$env:UV_PROJECT_ENVIRONMENT='C:\\pydivert_venv'; cd C:\\pydivert; C:\\pydivert_venv\\Scripts\\python.exe -m pytest --cov=pydivert --cov-report="]
        elif vm == "linux":
            # Disable rx/tx checksumming on lo
            run_cmd(["vagrant", "ssh", "linux", "-c", "sudo ethtool -K lo rx off tx off"])
            # Use local venv for execution
            cmd = ["vagrant", "ssh", "linux", "-c", "cd /home/vagrant/pydivert && echo 'vagrant' | sudo -S /home/vagrant/pydivert_venv/bin/python -m pytest --cov=pydivert --cov-report="]
        elif vm == "freebsd":
            # Load kernel module
            run_cmd(["vagrant", "ssh", "freebsd", "-c", "sudo kldload ipdivert || true"])
            # Sync files (FreeBSD uses rsync)
            run_cmd(["vagrant", "rsync", "freebsd"])
            # Use local venv
            cmd = ["vagrant", "ssh", "freebsd", "-c", "cd /vagrant && echo 'vagrant' | sudo -S /home/vagrant/pydivert_venv/bin/python -m pytest --cov=pydivert --cov-report="]

        run_cmd(cmd)

        # After each run, check for .coverage file and move it
        # Since VMs have synced folders, .coverage usually appears in the project root on the host.
        # But for FreeBSD (rsync), we might need to fetch it explicitly.

        if vm == "freebsd":
            # Sync back .coverage
            run_cmd(["vagrant", "ssh", "freebsd", "-c", "cp /vagrant/.coverage /home/vagrant/coverage.tmp"])
            # We don't have an easy way to rsync BACK automatically with vagrant rsync.
            # Use scp if needed, or rely on shared folders for others.
            # For simplicity, let's just try to find it in the current dir if it synced.

        local_cov = f".coverage.{vm}"
        if os.path.exists(".coverage"):
            shutil.move(".coverage", local_cov)
            coverage_files.append(local_cov)
            print(f"Collected coverage for {vm}")
        else:
            print(f"Warning: .coverage file not found for {vm} (check synced folders)")

    if coverage_files:
        print("\nCombining coverage reports...")
        # Check if uv is available for combining reports
        cov_cmd = ["uv", "tool", "run"] if shutil.which("uv") else []
        subprocess.run(cov_cmd + ["coverage", "combine"] + coverage_files)
        subprocess.run(cov_cmd + ["coverage", "report", "-m"])
        subprocess.run(cov_cmd + ["coverage", "html"])
        print("Consolidated report generated. See htmlcov/index.html")
    else:
        print("No coverage files collected.")

if __name__ == "__main__":
    main()
