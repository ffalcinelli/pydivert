# scripts/vagrant-provision.ps1
# This script installs uv and synchronizes dependencies for PyDivert testing on Windows.

Write-Host "Installing uv..."
# The guest resolves names through the host; retry transient network failures.
$installer = Join-Path $env:TEMP "install-uv.ps1"
for ($i = 1; $i -le 10; $i++) {
    try {
        Invoke-WebRequest -UseBasicParsing -Uri https://astral.sh/uv/install.ps1 -OutFile $installer -TimeoutSec 60
        break
    } catch {
        Write-Warning "Downloading the uv installer failed (attempt $i): $($_.Exception.Message)"
        Start-Sleep -Seconds 5
    }
}
if (!(Test-Path $installer)) {
    Write-Error "Could not download the uv installer"
    exit 1
}
powershell -ExecutionPolicy ByPass -File $installer
Remove-Item $installer

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

if (Test-Path "C:\pydivert") {
    cd C:\pydivert
    Write-Host "Installing dependencies with uv..."
    uv sync --extra test
} else {
    Write-Warning "C:\pydivert not found! Synced folder might not be mounted yet."
}

Write-Host "Provisioning complete."
