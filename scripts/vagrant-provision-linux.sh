#!/bin/bash
# scripts/vagrant-provision-linux.sh
set -e

echo "Provisioning Linux (Ubuntu)..."
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y python3-pip python3-venv libnetfilter-queue-dev curl git ethtool iptables

# Install uv for root and all users
curl -LsSf https://astral.sh/uv/install.sh | sh
# Ensure uv is in PATH for everyone
mv /root/.local/bin/uv /usr/local/bin/uv
mv /root/.local/bin/uvx /usr/local/bin/uvx

# Set VAGRANT_VM environment variable for troubleshooting tests
echo "export VAGRANT_VM=1" >> /home/vagrant/.bashrc
echo "export VAGRANT_VM=1" >> /root/.bashrc

# Enable routing of local traffic to allow NFQUEUE on loopback more easily
sysctl -w net.ipv4.conf.all.route_localnet=1

# Set up local virtual environment for Linux
VENV_PATH="/home/vagrant/pydivert_venv"
python3 -m venv "$VENV_PATH"
"$VENV_PATH/bin/pip" install --upgrade pip
"$VENV_PATH/bin/pip" install -e /home/vagrant/pydivert[test,linux]

# Also ensure uv works within the project folder
cd /home/vagrant/pydivert
uv sync --extra test --extra linux
