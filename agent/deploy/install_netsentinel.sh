#!/bin/bash
# NetSentinel Linux Bootstrap Installer (Debian/Ubuntu & RHEL/CentOS)
# Installs Python3, dependencies, and configures a systemd service.

echo "========================================"
echo "  NetSentinel Linux Agent Installer"
echo "========================================"

# 1. Check for root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Error: Please run as root (sudo)."
  exit 1
fi

# 2. Detect OS and Install Python3
if command -v apt-get &> /dev/null; then
    echo "[+] Detected Debian/Ubuntu. Installing python3..."
    apt-get update -qq && apt-get install -y python3 python3-pip
elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
    echo "[+] Detected RHEL/CentOS/Fedora. Installing python3..."
    yum install -y python3 python3-pip || dnf install -y python3 python3-pip
else
    echo "[!] Error: Unsupported package manager. Please install python3 manually."
    exit 1
fi

# 3. Setup Directory & Install Dependencies
INSTALL_DIR="/opt/netsentinel"
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

echo "[+] Installing Python dependencies..."
pip3 install requests psutil --break-system-packages --quiet 2>/dev/null || pip3 install requests psutil --quiet

# 4. Create Systemd Service
SERVICE_FILE="/etc/systemd/system/netsentinel.service"
cat <<EOF > $SERVICE_FILE
[Unit]
Description=NetSentinel Endpoint Security Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo "[+] Enabling and starting netsentinel service..."
systemctl daemon-reload
systemctl enable netsentinel.service
systemctl start netsentinel.service

echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
echo "Service is running. Check status with: systemctl status netsentinel"
echo "Next: Copy 'agent.py' and 'config.py' to $INSTALL_DIR and configure your API Token."