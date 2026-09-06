#!/bin/bash
# NetSentinel macOS Bootstrap Installer
# Installs Python via Homebrew and configures a launchd daemon.

echo "========================================"
echo "  NetSentinel macOS Agent Installer"
echo "========================================"

# 1. Check for root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Error: Please run with sudo."
  exit 1
fi

# 2. Install Python via Homebrew
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

# 3. Setup Directory & Install Dependencies
INSTALL_DIR="/usr/local/netsentinel"
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

echo "[+] Installing Python dependencies..."
pip3 install requests psutil --break-system-packages --quiet 2>/dev/null || pip3 install requests psutil --quiet

# 4. Create launchd Plist
PLIST_FILE="/Library/LaunchDaemons/com.netsentinel.agent.plist"
cat <<EOF > $PLIST_FILE
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.netsentinel.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/python3</string>
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
launchctl load -w $PLIST_FILE

echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
echo "Agent is running in the background."
echo "Next: Copy 'agent.py' and 'config.py' to $INSTALL_DIR and configure your API Token."