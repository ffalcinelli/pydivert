# scripts/provision-windows.ps1
# Installs uv and synchronizes dependencies for PyDivert testing on Windows.

param(
    [string]$SourceDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

Write-Host "Ensuring uv is installed..."
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
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
}

$uvPath = ""
$commonPaths = @("$env:USERPROFILE\.local\bin", "$env:USERPROFILE\.cargo\bin")
foreach ($p in $commonPaths) {
    if (Test-Path "$p\uv.exe") {
        $uvPath = $p
        break
    }
}

if ($uvPath) {
    if (-not ($env:Path -like "*$uvPath*")) {
        $env:Path = "$uvPath;$env:Path"
    }
    $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$uvPath*") {
        [System.Environment]::SetEnvironmentVariable("Path", "$uvPath;$userPath", "User")
    }
}

$env:UV_PROJECT_ENVIRONMENT = "C:\pydivert_venv"
# The newest CPython may have no wheels yet for some test dependencies (pyyaml); use the newest one CI tests.
if (-not $env:UV_PYTHON) { $env:UV_PYTHON = "3.14" }
if (Test-Path $SourceDir) {
    Set-Location $SourceDir
    Write-Host "Installing dependencies with uv..."
    uv sync --extra test
} else {
    Write-Warning "$SourceDir not found!"
}

Write-Host "Provisioning complete."
