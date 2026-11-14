#!/bin/bash
# ==============================================================================
# NetSentinel Linux Agent Installer (Zero-Touch Auto-Registration)
# FILENAME MUST BE: install_netsentinel.sh
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

# 4. Download and Extract Agent Archive (Fixes the curl | bash execution path)
echo "[+] Downloading agent package from server..."
DEPLOY_URL="https://netsentinel.timsansom.co.uk/deploy"
ARCHIVE_NAME="netsentinel-agent-linux.tar.gz"
TEMP_ARCHIVE="/tmp/$ARCHIVE_NAME"

if curl -sSL -o "$TEMP_ARCHIVE" "$DEPLOY_URL/$ARCHIVE_NAME"; then
    echo "[+] Extracting agent files..."
    tar -xzf "$TEMP_ARCHIVE" -C "$INSTALL_DIR"
    rm -f "$TEMP_ARCHIVE"
else
    echo "[!] tar.gz not found. Falling back to source zip..."
    ARCHIVE_NAME="netsentinel-agent-source.zip"
    TEMP_ARCHIVE="/tmp/$ARCHIVE_NAME"
    curl -sSL -o "$TEMP_ARCHIVE" "$DEPLOY_URL/$ARCHIVE_NAME"
    
    # Ensure unzip is available
    if command -v apt-get &> /dev/null; then apt-get install -y -qq unzip; fi
    if command -v yum &> /dev/null; then yum install -y -q unzip; fi
    
    unzip -q -o "$TEMP_ARCHIVE" -d /tmp/netsentinel-extract
    
    # Find the directory containing agent.py and copy its contents
    EXTRACTED_DIR=$(find /tmp/netsentinel-extract -name "agent.py" -exec dirname {} \; | head -n 1)
    if [ -n "$EXTRACTED_DIR" ]; then
        cp -r "$EXTRACTED_DIR"/* "$INSTALL_DIR/"
    else
        echo "[!] CRITICAL: Could not find agent.py in the downloaded package."
        exit 1
    fi
    rm -rf "$TEMP_ARCHIVE" /tmp/netsentinel-extract
fi

# Verify agent.py exists
if [ ! -f "$INSTALL_DIR/agent.py" ]; then
    echo "[!] CRITICAL ERROR: agent.py not found in $INSTALL_DIR after extraction."
    exit 1
fi
echo "[OK] Agent files extracted successfully to $INSTALL_DIR."

# 5. Install Python Dependencies
echo "[+] Installing Python dependencies (requests, psutil, schedule, python-dotenv)..."
python3 -m pip install requests psutil schedule python-dotenv --break-system-packages --quiet 2>/dev/null || \
python3 -m pip install requests psutil schedule python-dotenv --quiet

# 6. AUTO-GENERATE THE .env FILE (Zero-Touch Auto-Registration)
echo "[+] Generating secure configuration (.env)..."
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