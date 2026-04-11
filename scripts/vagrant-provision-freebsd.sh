#!/bin/sh
# scripts/vagrant-provision-freebsd.sh
set -e

echo "Provisioning FreeBSD..."

pkg update
pkg install -y python311 py311-pip py311-sqlite3 curl git

# Create symlink for python if it doesn't exist
if ! [ -x "$(command -v python)" ]; then
    ln -s /usr/local/bin/python3.11 /usr/local/bin/python
fi

# Load ipdivert and enable ipfw
if ! grep -q 'ipfw_enable="YES"' /etc/rc.conf; then
    echo 'ipfw_enable="YES"' >> /etc/rc.conf
    # Use 'open' firewall type to allow all traffic by default
    echo 'firewall_enable="YES"' >> /etc/rc.conf
    echo 'firewall_type="open"' >> /etc/rc.conf
    echo 'ipdivert_load="YES"' >> /etc/rc.conf
fi

# Apply immediately for current session
kldload ipfw || true
kldload ipdivert || true
# Try to enable loopback divert if the OID exists
sysctl net.inet.ip.divert_on_loopback=1 || true

service ipfw start || true

# Use a local virtual environment on the VM's local filesystem
# to avoid binary execution issues with shared folders (rsync/vboxsf)
VENV_PATH="/home/vagrant/pydivert_venv"
python3.11 -m venv "$VENV_PATH"
"$VENV_PATH/bin/pip" install --upgrade pip
"$VENV_PATH/bin/pip" install -e /vagrant[test]

# Add venv to path for convenience
echo "export PATH=\"$VENV_PATH/bin:\$PATH\"" >> /home/vagrant/.bash_profile
