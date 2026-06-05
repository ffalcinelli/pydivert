# scripts/run-tests-windows.ps1
# This script copies pydivert to a local folder and runs tests to avoid file locking on shared folders.

$SourceDir = "C:\pydivert"
$DestDir = "C:\pydivert_test"

Write-Host "Syncing project to local directory $DestDir..."
# Ensure DestDir exists
if (!(Test-Path $DestDir)) {
    New-Item -ItemType Directory -Force -Path $DestDir
}

# /MIR: Mirror, /XD: Exclude directories, /R:1: 1 retry, /W:1: 1s wait
# Robocopy exit codes 0-7 are generally success (no changes or only files copied/skipped)
robocopy $SourceDir $DestDir /MIR /XD .venv .git .vagrant .idea .antigravitycli .venv.old /XF *.json /R:1 /W:1 /NFL /NDL /NJH /NJS

if ($LASTEXITCODE -ge 8) {
    Write-Error "Robocopy failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

cd $DestDir

# Use a local virtual environment on the VM's C: drive to avoid issues with VirtualBox shared folders
$env:UV_PROJECT_ENVIRONMENT = "C:\pydivert_venv"

# Ensure uv is in Path
$uvPath = "C:\Users\vagrant\.local\bin"
if (Test-Path "$uvPath\uv.exe") {
    if (-not ($env:Path -like "*$uvPath*")) {
        $env:Path = "$uvPath;$env:Path"
    }
}

Write-Host "Ensuring dependencies are up to date..."
& uv sync --extra test

if ($LASTEXITCODE -ne 0) {
    Write-Error "uv sync failed"
    exit $LASTEXITCODE
}

Write-Host "Running tests with coverage..."
$env:COVERAGE_FILE = "C:\pydivert\.coverage.windows"
& uv run pytest --cov=pydivert --cov-config=.coveragerc pydivert\tests

if ($LASTEXITCODE -ne 0) {
    Write-Warning "Pytest encountered failures (Exit Code $LASTEXITCODE)"
}
