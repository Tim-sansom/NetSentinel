#!/bin/sh
# ==============================================================================
# NetSentinel FreeBSD/UNIX Bootstrap Installer (Zero-Touch Auto-Registration)
# ==============================================================================
# Installs Python3, copies agent files, installs dependencies, generates a 
# secure Zero-Touch config, and configures an rc.d startup script.
# ==============================================================================

echo "========================================"
echo "  NetSentinel FreeBSD Agent Installer"
echo "========================================"

# 1. Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: Please run as root."
    exit 1
fi

# 2. Install Python via pkg
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found. Installing via pkg..."
    pkg install -y python311 py311-pip
else
    echo "[OK] Python3 detected."
fi

# 3. Setup Installation Directory
INSTALL_DIR="/usr/local/netsentinel"
mkdir -p "$INSTALL_DIR"

# 4. Copy Agent Files from the extraction directory to the install directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
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
pip3 install requests psutil schedule python-dotenv --quiet

# 6. AUTO-GENERATE THE .env FILE (Zero-Touch Auto-Registration)
echo "[+] Generating secure configuration (.env)..."
# Generate unique UUIDs (tries native uuidgen first, falls back to python)
DEVICE_UUID=$(uuidgen 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())")
API_TOKEN=$(uuidgen 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())")

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

# 7. Create rc.d script for Persistence
RC_FILE="/usr/local/etc/rc.d/netsentinel"
cat <<EOF > "$RC_FILE"
#!/bin/sh
# PROVIDE: netsentinel
# REQUIRE: DAEMON NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="netsentinel"
rcvar="netsentinel_enable"

command="/usr/local/bin/python3"
command_args="/usr/local/netsentinel/agent.py"
pidfile="/var/run/\${name}.pid"
command_interpreter="/usr/local/bin/python3"

load_rc_config \$name
run_rc_command "\$1"
EOF
chmod +x "$RC_FILE"

# 8. Enable in rc.conf and start service
sysrc netsentinel_enable="YES"
echo "[+] Starting netsentinel service..."
service netsentinel start

# 9. Verify Status
echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
if service netsentinel status > /dev/null 2>&1; then
    echo "[+] Service is running successfully."
else
    echo "[!] Warning: Service failed to start. Check logs or run: service netsentinel status"
fi
echo "Check status with: service netsentinel status"