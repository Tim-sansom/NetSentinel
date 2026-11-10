# NetSentinel Windows Installer - Compilation Guide

## Source Files
The following files are used to create the Windows installer:

1. **NetSentinelInstaller.iss** - Inno Setup script (installer source code)
2. **install_netsentinel.ps1** - PowerShell bootstrap script
3. **agent.py** - Python agent source code
4. **config.py** - Configuration file template
5. **README.txt** - User documentation

## Compilation Process

### Prerequisites
- Inno Setup 6.x (free, open-source)
  - Download: https://jrsoftware.org/isdl.php
  - License: Inno Setup License (free for commercial use)

### Steps to Compile

1. **Install Inno Setup**