#!/bin/bash
# scripts/vagrant-provision-macos.sh
set -e

echo "Provisioning macOS..."

# Install Homebrew if not present
if ! command -v brew >/dev/null 2>&1; then
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    (echo; echo 'eval "$(/usr/local/bin/brew shellenv)"') >> /Users/vagrant/.zprofile
    eval "$(/usr/local/bin/brew shellenv)"
fi

# Install prerequisites
brew install python@3.11 uv git

# Sync dependencies
export PATH="/usr/local/bin:$PATH"
cd /Users/vagrant/pydivert
uv sync --extra test
