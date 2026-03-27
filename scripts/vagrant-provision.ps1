# scripts/vagrant-provision.ps1
# This script installs uv and synchronizes dependencies for PyDivert testing on Windows.

Write-Host "Installing uv..."
Invoke-WebRequest -Uri https://astral.sh/uv/install.ps1 -OutFile install-uv.ps1
powershell -ExecutionPolicy ByPass -File install-uv.ps1
Remove-Item install-uv.ps1

# Add uv to the current session's path
$uvPath = "$HOME\.cargo\bin"
if (-not ($env:Path -like "*$uvPath*")) {
    $env:Path += ";$uvPath"
}

# Use a local virtual environment on the VM's C: drive to avoid issues with VirtualBox shared folders
$env:UV_PROJECT_ENVIRONMENT = "C:\pydivert_venv"

cd C:\pydivert

Write-Host "Installing dependencies with uv..."
uv sync --extra test

Write-Host "Provisioning complete. You can now run tests with 'uv run pytest' as Administrator."
