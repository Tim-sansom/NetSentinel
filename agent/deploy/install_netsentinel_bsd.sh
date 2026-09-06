#!/bin/sh
# NetSentinel FreeBSD/UNIX Bootstrap Installer
# Installs Python3 and configures an rc.d startup script.

echo "========================================"
echo "  NetSentinel FreeBSD Agent Installer"
echo "========================================"

# 1. Check for root
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

# 3. Setup Directory & Install Dependencies
INSTALL_DIR="/usr/local/netsentinel"
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

echo "[+] Installing Python dependencies..."
pip3 install requests psutil --quiet

# 4. Create rc.d script
RC_FILE="/usr/local/etc/rc.d/netsentinel"
cat <<EOF > $RC_FILE
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

chmod +x $RC_FILE

# Enable in rc.conf
sysrc netsentinel_enable="YES"
echo "[+] Starting netsentinel service..."
service netsentinel start

echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
echo "Agent is running. Check status with: service netsentinel status"
echo "Next: Copy 'agent.py' and 'config.py' to $INSTALL_DIR and configure your API Token."