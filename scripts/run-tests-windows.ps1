# scripts/run-tests-windows.ps1
# This script copies pydivert to a local folder and runs tests to avoid file locking on shared folders.

$SourceDir = "C:\pydivert"
$DestDir = "C:\pydivert_test"

Write-Host "Syncing project to local directory $DestDir..."
# /MIR: Mirror, /XD: Exclude directories, /R:0: No retries
robocopy $SourceDir $DestDir /MIR /XD .venv .git .vagrant .idea /R:0 /W:0

if ($LASTEXITCODE -ge 8) {
    Write-Warning "Robocopy encountered errors (Code $LASTEXITCODE)"
}

cd $DestDir

# Use a local virtual environment on the VM's C: drive to avoid issues with VirtualBox shared folders
$env:UV_PROJECT_ENVIRONMENT = "C:\pydivert_venv"

# Find where uv was installed
$uvPath = ""
$commonPaths = @("$HOME\.local\bin", "$HOME\.cargo\bin", "C:\Users\vagrant\.local\bin")
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
}

Write-Host "Ensuring dependencies are up to date..."
uv sync --extra test

Write-Host "Running tests with coverage..."
$env:COVERAGE_FILE = "C:\pydivert\.coverage.windows"
uv run pytest --cov=pydivert --cov-config=.coveragerc pydivert\tests
