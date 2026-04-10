#!/bin/bash
# scripts/vagrant-provision-linux.sh
set -e

echo "Provisioning Linux (Ubuntu)..."
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y python3-pip python3-venv libnetfilter-queue-dev curl git

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> /home/vagrant/.bashrc

# Sync dependencies
export PATH="$HOME/.local/bin:$PATH"
cd /home/vagrant/pydivert
uv sync --extra test
