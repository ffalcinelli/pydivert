#!/bin/bash
# scripts/vagrant-provision-macos.sh
set -e

echo "Provisioning macOS..."

# Check if brew is installed, if not, it's problematic on CI but should be on dev boxes
if ! command -v brew >/dev/null 2>&1; then
    echo "Warning: Homebrew not found. Trying to install dependencies via pip..."
fi

# Use a local virtual environment for macOS
VENV_PATH="/Users/vagrant/pydivert_venv"
python3 -m venv "$VENV_PATH"
"$VENV_PATH/bin/pip" install --upgrade pip
"$VENV_PATH/bin/pip" install -e /Users/vagrant/pydivert[test]

# Install uv if possible
if command -v brew >/dev/null 2>&1; then
    brew install uv
else
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi
