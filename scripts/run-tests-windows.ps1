# scripts/run-tests-windows.ps1
# Copies pydivert to a local folder and runs tests to avoid file locking on shared folders.

param(
    [string]$SourceDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$DestDir = "C:\pydivert_test"
)

Write-Host "Syncing project from $SourceDir to $DestDir..."
if (!(Test-Path $DestDir)) {
    New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
}

robocopy $SourceDir $DestDir /MIR /XD .venv .git .idea .antigravitycli .venv.old /XF *.json /R:1 /W:1 /NFL /NDL /NJH /NJS

if ($LASTEXITCODE -ge 8) {
    Write-Error "Robocopy failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Set-Location $DestDir

# Use a local virtual environment on C: to avoid issues with synced folders
$env:UV_PROJECT_ENVIRONMENT = "C:\pydivert_venv"

# Ensure uv is in Path
foreach ($uvPath in @("$env:USERPROFILE\.local\bin", "$env:USERPROFILE\.cargo\bin")) {
    if (Test-Path "$uvPath\uv.exe") {
        if (-not ($env:Path -like "*$uvPath*")) {
            $env:Path = "$uvPath;$env:Path"
        }
        break
    }
}

Write-Host "Ensuring dependencies are up to date..."
& uv sync --extra test

if ($LASTEXITCODE -ne 0) {
    Write-Error "uv sync failed"
    exit $LASTEXITCODE
}

Write-Host "Fetching pre-built binaries..."
& uv run python scripts/fetch_binaries.py

Write-Host "Running tests with coverage..."
$env:COVERAGE_FILE = Join-Path $SourceDir ".coverage.windows"
& uv run pytest --cov=pydivert --cov-config=.coveragerc pydivert\tests

if ($LASTEXITCODE -ne 0) {
    Write-Warning "Pytest encountered failures (Exit Code $LASTEXITCODE)"
    exit $LASTEXITCODE
}
