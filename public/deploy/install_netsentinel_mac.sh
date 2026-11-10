#!/bin/bash
# ==============================================================================
# NetSentinel macOS Bootstrap Installer (Zero-Touch Auto-Registration)
# ==============================================================================
# Installs Python via Homebrew, copies agent files, installs dependencies, 
# generates a secure Zero-Touch config, and configures a launchd daemon.
#
# ACADEMIC SIGNIFICANCE:
# Demonstrates cross-platform deployment consistency. Implements Zero-Touch 
# Provisioning (ZTP) by auto-generating cryptographic UUIDs for both device 
# identity and API authentication, satisfying SR2 (Access Control).
# ==============================================================================

echo "========================================"
echo "  NetSentinel macOS Agent Installer"
echo "========================================"

# 1. Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "[!] Error: Please run with sudo."
    exit 1
fi

# 2. Install Python via Homebrew if missing
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found. Attempting to install via Homebrew..."
    if ! command -v brew &> /dev/null; then
        echo "[!] Homebrew not found. Please install Homebrew or Python3 manually."
        exit 1
    fi
    brew install python
else
    echo "[OK] Python3 detected: $(python3 --version)"
fi

# Get the exact path to python3 (Handles both Intel and Apple Silicon Macs)
PYTHON_BIN=$(which python3)
echo "[OK] Python3 binary located at: $PYTHON_BIN"

# 3. Setup Installation Directory
INSTALL_DIR="/usr/local/netsentinel"
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
$PYTHON_BIN -m pip install requests psutil schedule python-dotenv --quiet 2>/dev/null || $PYTHON_BIN -m pip install requests psutil schedule python-dotenv --quiet

# 6. AUTO-GENERATE THE .env FILE (Zero-Touch Auto-Registration)
echo "[+] Generating secure configuration (.env)..."
# Generate unique UUIDs for Device Identity and API Authentication (SR2)
DEVICE_UUID=$($PYTHON_BIN -c "import uuid; print(uuid.uuid4())")
API_TOKEN=$($PYTHON_BIN -c "import uuid; print(uuid.uuid4())")

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

# 7. Create launchd Plist for Persistence
PLIST_FILE="/Library/LaunchDaemons/com.netsentinel.agent.plist"

# Unload existing daemon to prevent conflicts during re-installation
if [ -f "$PLIST_FILE" ]; then
    echo "[+] Unloading existing daemon..."
    launchctl unload -w "$PLIST_FILE" 2>/dev/null || true
fi

cat <<EOF > "$PLIST_FILE"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.netsentinel.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_BIN</string>
        <string>$INSTALL_DIR/agent.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/netsentinel.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/netsentinel-error.log</string>
</dict>
</plist>
EOF

echo "[+] Loading launchd daemon..."
launchctl load -w "$PLIST_FILE"

# 8. Verify Status
echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
if launchctl list | grep -q "com.netsentinel.agent"; then
    echo "[+] Daemon loaded and running successfully."
else
    echo "[!] Warning: Daemon failed to load. Check logs: cat /var/log/netsentinel-error.log"
fi
echo "Check status with: launchctl list | grep com.netsentinel.agent"