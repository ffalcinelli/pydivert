# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import subprocess
import os
import shutil

VM_CONFIGS = {
    "windows": {
        "shell": "powershell",
        "env": "$env:UV_PROJECT_ENVIRONMENT='C:/pydivert_venv'; cd C:/pydivert",
        "command": "uv run pytest --cov=pydivert --cov-append --cov-report=None",
        "coverage_file": "C:/pydivert/.coverage"
    },
    "linux": {
        "shell": "bash",
        "env": "cd /home/vagrant/pydivert",
        "command": "export PATH=$HOME/.local/bin:$PATH; uv run pytest --cov=pydivert --cov-append --cov-report=None",
        "coverage_file": "/home/vagrant/pydivert/.coverage"
    },
    "freebsd": {
        "shell": "bash",
        "env": "cd /vagrant",
        "command": "export PATH=$HOME/.local/bin:$PATH; uv run pytest --cov=pydivert --cov-append --cov-report=None",
        "coverage_file": "/vagrant/.coverage"
    }
}

def run_command(vm, command):
    print(f"--- Running tests on {vm} ---")
    full_command = f"vagrant ssh {vm} -c '{command}'"
    if vm == "windows":
        full_command = f"vagrant powershell {vm} -c \"{VM_CONFIGS[vm]['env']}; {VM_CONFIGS[vm]['command']}\""
    else:
        full_command = f"vagrant ssh {vm} -c \"{VM_CONFIGS[vm]['env']} && {VM_CONFIGS[vm]['command']}\""
    
    try:
        subprocess.run(full_command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running tests on {vm}: {e}")

def aggregate_coverage():
    print("--- Aggregating coverage ---")
    # This assumes .coverage files were generated in the synced folders
    subprocess.run("coverage combine", shell=True)
    subprocess.run("coverage report", shell=True)
    subprocess.run("coverage html", shell=True)
    print("Aggregated coverage report generated in htmlcov/index.html")

if __name__ == "__main__":
    for vm in VM_CONFIGS.keys():
        run_command(vm, VM_CONFIGS[vm]["command"])
    
    aggregate_coverage()
