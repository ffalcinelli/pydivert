# scripts/vagrant-provision.ps1
# This script installs uv and synchronizes dependencies for PyDivert testing on Windows.

Write-Host "Installing uv..."
Invoke-WebRequest -Uri https://astral.sh/uv/install.ps1 -OutFile install-uv.ps1
powershell -ExecutionPolicy ByPass -File install-uv.ps1
Remove-Item install-uv.ps1

# Find where uv was installed
$uvPath = ""
$commonPaths = @("$HOME\.local\bin", "$HOME\.cargo\bin")
foreach ($p in $commonPaths) {
    if (Test-Path "$p\uv.exe") {
        $uvPath = $p
        break
    }
}

if ($uvPath) {
    Write-Host "Found uv at $uvPath"
    if (-not ($env:Path -like "*$uvPath*")) {
        $env:Path = "$uvPath;$env:Path"
    }

    # Ensure uv is in the User PATH permanently
    $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$uvPath*") {
        Write-Host "Adding $uvPath to User PATH"
        [System.Environment]::SetEnvironmentVariable("Path", "$uvPath;$userPath", "User")
    }
} else {
    Write-Warning "uv.exe not found in common locations!"
}

# Use a local virtual environment on the VM's C: drive to avoid issues with VirtualBox shared folders
$env:UV_PROJECT_ENVIRONMENT = "C:\pydivert_venv"

cd C:\pydivert

Write-Host "Installing dependencies with uv..."
uv sync --extra test

Write-Host "Provisioning complete. You can now run tests with 'uv run pytest' as Administrator."
