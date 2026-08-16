#!/usr/bin/env bash
set -euo pipefail

# Configurations
VMS=("192.168.122.35" "192.168.122.6")
SSH_USER="debian"
SERVICE_FILE="contrib/systemd/debvulns-exporter.service"

echo "=== Step 1: Building package locally ==="
uv build

# Dynamically pick the most recently built wheel so the name never goes stale
SRC_WHL=$(ls -t dist/debvulns-*.whl 2>/dev/null | head -1)
if [ -z "${SRC_WHL}" ]; then
    echo "Error: No debvulns wheel found in dist/ after build!"
    exit 1
fi
WHL_NAME=$(basename "${SRC_WHL}")
echo "-> Using wheel: ${WHL_NAME}"

for VM in "${VMS[@]}"; do
    echo ""
    echo "========================================="
    echo " Deploying to VM: ${VM}"
    echo "========================================="

    # 1. Copy the wheel and service file to remote /tmp
    echo "-> Copying package and service files to remote VM..."
    scp -o StrictHostKeyChecking=no "${SRC_WHL}" "${SERVICE_FILE}" "${SSH_USER}@${VM}:/tmp/"

    # 2. Execute installation script on remote VM
    echo "-> Running remote installation commands..."
    ssh -o StrictHostKeyChecking=no "${SSH_USER}@${VM}" "WHL_NAME=${WHL_NAME} bash -s" << 'EOF'
set -euo pipefail

WHL_FILE="/tmp/${WHL_NAME}"
SRV_FILE="/tmp/debvulns-exporter.service"

# A. Clean up old debsecan deployment if present
if systemctl is-active --quiet debsecan-exporter.service || systemctl is-enabled --quiet debsecan-exporter.service; then
    echo "Cleaning up legacy debsecan-exporter service..."
    sudo systemctl stop debsecan-exporter.service || true
    sudo systemctl disable debsecan-exporter.service || true
fi
sudo rm -f /etc/systemd/system/debsecan-exporter.service
sudo rm -f /usr/local/bin/debsecan-exporter
sudo rm -f /usr/local/bin/debsecan-mcp
sudo rm -rf /opt/debsecan

if getent passwd debsecan > /dev/null; then
    echo "Removing legacy debsecan user..."
    sudo userdel -r debsecan || true
fi
if getent group debsecan > /dev/null; then
    sudo groupdel debsecan || true
fi

# B. Install/Verify uv for debian user
if [ ! -f ~/.local/bin/uv ]; then
    echo "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH="$HOME/.local/bin:$PATH"

# C. Setup System User and Group
if ! getent group debvulns > /dev/null; then
    echo "Creating debvulns group..."
    sudo groupadd -r debvulns
fi
if ! getent passwd debvulns > /dev/null; then
    echo "Creating debvulns system user..."
    sudo useradd -r -g debvulns -d /var/cache/debvulns-exporter -s /usr/sbin/nologin debvulns
fi

# D. Setup App Directory and Python Virtualenv
echo "Setting up /opt/debvulns..."
sudo mkdir -p /opt/debvulns
sudo chown debian:debian /opt/debvulns

# Comply with ProtectHome=true guidelines
export UV_PYTHON_INSTALL_DIR=/opt/debvulns/python

echo "Creating virtual environment..."
uv venv /opt/debvulns/venv --python 3.11

echo "Installing package..."
uv pip install --python /opt/debvulns/venv "${WHL_FILE}"

# E. Symlink binaries to /usr/local/bin
echo "Symlinking binaries..."
sudo ln -sf /opt/debvulns/venv/bin/debvulns /usr/local/bin/debvulns
sudo ln -sf /opt/debvulns/venv/bin/debvulns-mcp /usr/local/bin/debvulns-mcp
sudo ln -sf /opt/debvulns/venv/bin/debvulns-exporter /usr/local/bin/debvulns-exporter

# F. Configure Cache Directory
echo "Configuring cache directory..."
sudo mkdir -p /var/cache/debvulns-exporter
sudo chown debvulns:debvulns /var/cache/debvulns-exporter
sudo chmod 750 /var/cache/debvulns-exporter

# G. Setup and Start Systemd Service
echo "Installing systemd service..."
sudo cp "${SRV_FILE}" /etc/systemd/system/debvulns-exporter.service
sudo chown root:root /etc/systemd/system/debvulns-exporter.service
sudo chmod 644 /etc/systemd/system/debvulns-exporter.service

echo "Starting debvulns-exporter service..."
sudo systemctl daemon-reload
sudo systemctl enable debvulns-exporter.service
sudo systemctl restart debvulns-exporter.service

# H. Clean up temp files
rm -f "${WHL_FILE}" "${SRV_FILE}"

echo "=== VM Installation Complete ==="
EOF

done

echo "========================================="
echo "All deployments finished!"
echo "========================================="
