#!/bin/bash
# ==============================================================================
# NetSentinel macOS Bootstrap Installer (Zero-Touch Auto-Registration)
# ==============================================================================
# Installs Python via Homebrew, DOWNLOADS + extracts the agent archive,
# installs deps, generates a secure idempotent Zero-Touch config, and
# configures a launchd daemon.
#
# ACADEMIC SIGNIFICANCE:
# Demonstrates cross-platform deployment consistency. The curl|bash model
# means the script has no on-disk location, so it must self-fetch its
# payload (mirrors install_netsentinel.sh). Idempotent credential reuse
# prevents duplicate device records (FR1/NFR1). Auto-generated UUIDs for
# device identity + API token satisfy SR2 (Access Control).
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

PYTHON_BIN=$(which python3)
echo "[OK] Python3 binary located at: $PYTHON_BIN"

# 3. Setup Installation Directory
INSTALL_DIR="/usr/local/netsentinel"
mkdir -p "$INSTALL_DIR"

# 4. DOWNLOAD + extract agent archive (curl|bash has no SCRIPT_DIR)
echo "[+] Downloading agent package from server..."
DEPLOY_URL="https://netsentinel.timsansom.co.uk/deploy"
ARCHIVE_NAME="netsentinel-agent-macos.tar.gz"
TEMP_ARCHIVE="/tmp/$ARCHIVE_NAME"

if curl -f -sSL -o "$TEMP_ARCHIVE" "$DEPLOY_URL/$ARCHIVE_NAME?t=$(date +%s)"; then
    echo "[+] Extracting agent files..."
    tar -xzf "$TEMP_ARCHIVE" -C "$INSTALL_DIR"
    rm -f "$TEMP_ARCHIVE"
else
    echo "[!] tar.gz not found. Falling back to source zip..."
    ARCHIVE_NAME="netsentinel-agent-source.zip"
    TEMP_ARCHIVE="/tmp/$ARCHIVE_NAME"
    curl -f -sSL -o "$TEMP_ARCHIVE" "$DEPLOY_URL/$ARCHIVE_NAME?t=$(date +%s)"
    if command -v unzip &> /dev/null; then
        unzip -q -o "$TEMP_ARCHIVE" -d /tmp/netsentinel-extract
        EXTRACTED_DIR=$(find /tmp/netsentinel-extract -name "agent.py" -exec dirname {} \; | head -n 1)
        if [ -n "$EXTRACTED_DIR" ]; then
            cp -r "$EXTRACTED_DIR"/* "$INSTALL_DIR/"
        else
            echo "[!] CRITICAL: Could not find agent.py in downloaded package."
            exit 1
        fi
        rm -rf "$TEMP_ARCHIVE" /tmp/netsentinel-extract
    else
        echo "[!] CRITICAL: unzip not available and tar.gz download failed."
        exit 1
    fi
fi

if [ ! -f "$INSTALL_DIR/agent.py" ]; then
    echo "[!] CRITICAL ERROR: agent.py not found in $INSTALL_DIR after extraction."
    exit 1
fi
echo "[OK] Agent files extracted successfully to $INSTALL_DIR."

# 5. Install Python dependencies (PEP 668 aware for Homebrew Python)
echo "[+] Installing Python dependencies (requests, psutil, schedule, python-dotenv)..."
$PYTHON_BIN -m pip install requests psutil schedule python-dotenv --break-system-packages --quiet 2>/dev/null || \
$PYTHON_BIN -m pip install requests psutil schedule python-dotenv --quiet

# 6. AUTO-GENERATE / REUSE .env (Zero-Touch, IDEMPOTENT)
if [ -f "$INSTALL_DIR/.env" ] && grep -q "NETSENTINEL_DEVICE_UUID" "$INSTALL_DIR/.env"; then
    echo "[+] Existing agent identity found - reusing (no duplicate device created)."
    DEVICE_UUID=$(grep NETSENTINEL_DEVICE_UUID "$INSTALL_DIR/.env" | cut -d= -f2)
    API_TOKEN=$(grep NETSENTINEL_API_TOKEN "$INSTALL_DIR/.env" | cut -d= -f2)
else
    echo "[+] Generating secure configuration (.env)..."
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
fi

# 7. Create launchd Plist for Persistence
PLIST_FILE="/Library/LaunchDaemons/com.netsentinel.agent.plist"
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