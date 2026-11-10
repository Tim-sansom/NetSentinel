#!/bin/bash
# ==============================================================================
# NetSentinel Linux Bootstrap Installer (Zero-Touch Auto-Registration)
# ==============================================================================
# Installs Python3, dependencies, copies agent files, generates a secure 
# Zero-Touch config, and configures a systemd service.
# Supports Debian/Ubuntu (apt) and RHEL/CentOS/Fedora (yum/dnf).
# ==============================================================================

echo "========================================"
echo "  NetSentinel Linux Agent Installer"
echo "========================================"

# 1. Check for root privileges
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

# 3. Setup Installation Directory
INSTALL_DIR="/opt/netsentinel"
mkdir -p "$INSTALL_DIR"

# 4. Copy Agent Files from the extraction directory to the install directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ ! -f "$SCRIPT_DIR/agent.py" ]; then
    echo "[!] Error: agent.py not found in $SCRIPT_DIR. Please run this script from the extracted folder."
    exit 1
fi

echo "[+] Copying agent files from $SCRIPT_DIR to $INSTALL_DIR..."
cp "$SCRIPT_DIR/agent.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/config.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/logger.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/api_client.py" "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/checks" "$INSTALL_DIR/" 2>/dev/null || true
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/" 2>/dev/null || true

# 5. Install Python Dependencies
echo "[+] Installing Python dependencies (requests, psutil, schedule, python-dotenv)..."
# Using --break-system-packages for PEP 668 compliance on newer Debian/Ubuntu
python3 -m pip install requests psutil schedule python-dotenv --break-system-packages --quiet 2>/dev/null || python3 -m pip install requests psutil schedule python-dotenv --quiet

# 6. AUTO-GENERATE THE .env FILE (Zero-Touch Auto-Registration)
echo "[+] Generating secure configuration (.env)..."
# Generate unique UUIDs for Device Identity and API Authentication (SR2)
DEVICE_UUID=$(python3 -c "import uuid; print(uuid.uuid4())")
API_TOKEN=$(python3 -c "import uuid; print(uuid.uuid4())")

cat <<EOF > "$INSTALL_DIR/.env"
# NetSentinel Agent Configuration (Zero-Touch)
NETSENTINEL_API_URL=https://netsentinel.timsansom.co.uk/api
NETSENTINEL_API_TOKEN=$API_TOKEN
NETSENTINEL_DEVICE_UUID=$DEVICE_UUID
NETSENTINEL_CHECK_INTERVAL=300
NETSENTINEL_REQUEST_TIMEOUT=30
NETSENTINEL_LOG_LEVEL=INFO
NETSENTINEL_VERIFY_SSL=true
EOF
echo "[OK] Configuration generated with unique Device UUID and API Token."

# 7. Create Systemd Service for Persistence
SERVICE_FILE="/etc/systemd/system/netsentinel.service"
cat <<EOF > "$SERVICE_FILE"
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

# 8. Verify Status
echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
if systemctl is-active --quiet netsentinel.service; then
    echo "[+] Service is running successfully."
else
    echo "[!] Warning: Service failed to start. Check logs with: journalctl -u netsentinel.service"
fi
echo "Check status with: systemctl status netsentinel"