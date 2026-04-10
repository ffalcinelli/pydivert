#!/bin/sh
# scripts/vagrant-provision-freebsd.sh
set -e

echo "Provisioning FreeBSD..."

pkg update
pkg install -y python311 py311-pip py311-sqlite3 curl git

# Install uv - NOT AVAILABLE ON FREEBSD
# curl -LsSf https://astral.sh/uv/install.sh | sh
# echo 'export PATH="$HOME/.local/bin:$PATH"' >> /home/vagrant/.bash_profile

# Create symlink for python if it doesn't exist to ensure consistency
if ! [ -x "$(command -v python)" ]; then
    ln -s /usr/local/bin/python3.11 /usr/local/bin/python
fi

# Sync dependencies using pip instead of uv
cd /vagrant
python3.11 -m venv .venv
. .venv/bin/activate
pip install -e .[test]
