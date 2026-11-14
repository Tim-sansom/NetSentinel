<#
==============================================================================
NetSentinel Windows Agent - Zero-Touch Deployment Script (Production Ready)
Author: Tim Sansom (University Dissertation Project)
==============================================================================

PURPOSE:
Performs a fully automated, single-command deployment of the NetSentinel
endpoint agent onto a Windows 10/11 host. It downloads the agent package,
resolves a real Python interpreter, installs dependencies, generates a unique
per-device credential bundle (.env), and registers a resilient Scheduled Task.

ACADEMIC SIGNIFICANCE (FRD5 / NFR3 - SME-Friendly Provisioning):
Demonstrates Zero-Touch Provisioning (ZTP) for non-technical SME admins. The
installer is idempotent and self-healing: it never requires the operator to
pre-install Python or manually create tokens.

RESILIENCE NOTE (FED-004 / D-096):
On fresh or unpatched Windows 10 images the winget source metadata is often
uninitialised (the msstore source has not accepted its agreements), so winget
fails with "0x8a15000f : Data required by the source is missing" and aborts the
whole install. A resilient installer must not depend on a single, fragile
package manager. Python resolution therefore proceeds in three tiers:
  (a) an existing known Python install,
  (b) winget (best-effort, non-fatal),
  (c) a direct silent download from python.org (deterministic fallback),
re-detecting the interpreter after each attempt.

SECURITY BOUNDARIES:
- SR1: All downloads use HTTPS (TLS 1.2 enforced).
- SR2: Generates a unique per-device UUID + API token; the server performs
  Zero-Touch auto-registration (see auth.php / submit.php).
- NFR1: Lightweight - no persistent service, a single Scheduled Task only.

@version 1.1 (winget resilience fallback + .env path fix)
@date    2026
==============================================================================
#>

# ---------------------------------------------------------------------------
# 1. Enforce Administrator Privileges
# ---------------------------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[!] CRITICAL ERROR: This script must be run as Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  NetSentinel Windows Agent Installer (Zero-Touch)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$installDir = "C:\Program Files\NetSentinel"
$deployUrl  = "https://netsentinel.timsansom.co.uk/deploy"
# FIXED: Added /api to the base URL so the agent points to the correct endpoint
$apiUrl     = "https://netsentinel.timsansom.co.uk/api"

# ---------------------------------------------------------------------------
# 2. Create Installation Directory
# ---------------------------------------------------------------------------
Write-Host "`n[+] Preparing installation directory..." -ForegroundColor Yellow
if (!(Test-Path $installDir)) {
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
}

# ---------------------------------------------------------------------------
# 3. Download, Extract, and FLATTEN Agent Source Code
# ---------------------------------------------------------------------------
Write-Host "[+] Downloading full agent package from server..." -ForegroundColor Yellow
$zipUrl = "$deployUrl/netsentinel-agent-source.zip"
$tempZipPath = "$env:TEMP\netsentinel-agent-source.zip"
$tempExtractPath = "$env:TEMP\netsentinel-extract"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $zipUrl -OutFile $tempZipPath -UseBasicParsing
    if (Test-Path $tempExtractPath) { Remove-Item -Recurse -Force $tempExtractPath }
    Expand-Archive -Path $tempZipPath -DestinationPath $tempExtractPath -Force

    # Locate agent.py wherever it landed, then flatten its directory into the install dir.
    $agentRoot = Get-ChildItem -Path $tempExtractPath -Recurse -Filter "agent.py" | Select-Object -First 1 -ExpandProperty DirectoryName
    if ($agentRoot) {
        Copy-Item -Path "$agentRoot\*" -Destination $installDir -Recurse -Force
        Write-Host "[OK] Agent files extracted and flattened successfully to $installDir." -ForegroundColor Green
    } else {
        throw "Could not find agent.py inside the downloaded package."
    }

    Remove-Item $tempZipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $tempExtractPath -Recurse -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host "[!] CRITICAL ERROR: Failed to download or extract agent package. Error: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# ---------------------------------------------------------------------------
# 4. Find or Install Real Python (Ignoring Windows Store Stub)
#    + winget resilience fallback to direct python.org download (FED-004)
# ---------------------------------------------------------------------------
function Get-NetsentinelPython {
    $knownPaths = @(
        "C:\Program Files\Python311\python.exe",
        "C:\Program Files\Python312\python.exe",
        "C:\Program Files\Python310\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe"
    )
    foreach ($p in $knownPaths) {
        if (Test-Path $p) { return $p }
    }
    # Reject the Microsoft Store stub (WindowsApps) which is not a real interpreter.
    $cmd = Get-Command python.exe -All -ErrorAction SilentlyContinue |
           Where-Object { $_.Source -notlike "*WindowsApps*" } |
           Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    return $null
}

$pythonPath = Get-NetsentinelPython

if (-not $pythonPath) {
    Write-Host "[!] Python not found. Attempting install via winget..." -ForegroundColor Yellow
    try {
        winget install -e --id Python.Python.3.11 --scope machine --silent `
            --accept-package-agreements --accept-source-agreements
    } catch {
        Write-Host "[!] winget raised an error (source may be uninitialised on this image)." -ForegroundColor Yellow
    }
    # Refresh PATH so a machine-wide install is visible to this session.
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path","User")
    $pythonPath = Get-NetsentinelPython
}

if (-not $pythonPath) {
    # RESILIENCE FALLBACK: winget is unreliable on stale/unpatched endpoints
    # (the exact SME population NetSentinel targets). Download the official
    # installer directly and perform a silent per-machine install.
    Write-Host "[!] winget unavailable. Falling back to direct Python download from python.org..." -ForegroundColor Yellow
    $pyInstaller = Join-Path $env:TEMP "python-3.11.9-amd64.exe"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe" `
            -OutFile $pyInstaller -UseBasicParsing
        Start-Process -FilePath $pyInstaller `
            -ArgumentList "/quiet","InstallAllUsers=1","PrependPath=1","Include_test=0" `
            -Wait
        Remove-Item $pyInstaller -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "[!] Direct Python download failed: $_" -ForegroundColor Red
    }
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path","User")
    $pythonPath = Get-NetsentinelPython
}

if (-not $pythonPath) {
    Write-Host "[!] CRITICAL ERROR: Could not locate or install a valid Python interpreter." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "[OK] Using real Python at: $pythonPath" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. Ensure pip is installed and Install Dependencies
# ---------------------------------------------------------------------------
Write-Host "[+] Ensuring pip package manager is available..." -ForegroundColor Yellow
& $pythonPath -m ensurepip --upgrade | Out-Null

Write-Host "[+] Installing required Python dependencies..." -ForegroundColor Yellow
try {
    & $pythonPath -m pip install requests psutil schedule python-dotenv --quiet
    if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
    Write-Host "[OK] Dependencies installed successfully." -ForegroundColor Green
} catch {
    Write-Host "[!] ERROR: Failed to install dependencies." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# ---------------------------------------------------------------------------
# 6. Generate Configuration (.env)
#    FIXED: Use Join-Path so the file lands inside the install directory
#    (matching the Linux/macOS/BSD scripts) rather than beside it.
# ---------------------------------------------------------------------------
Write-Host "[+] Generating secure configuration (.env)..." -ForegroundColor Yellow
$uuid  = [guid]::NewGuid().ToString()
$token = [guid]::NewGuid().ToString()
$envContent = @"
NETSENTINEL_API_URL=$apiUrl
NETSENTINEL_API_TOKEN=$token
NETSENTINEL_DEVICE_UUID=$uuid
CHECK_INTERVAL=300
"@
Set-Content -Path (Join-Path $installDir ".env") -Value $envContent -Force
Write-Host "[OK] Configuration generated with unique Device UUID and API Token." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 7. Create Scheduled Task for Persistence
# ---------------------------------------------------------------------------
Write-Host "[+] Configuring Windows Scheduled Task..." -ForegroundColor Yellow
$taskName = "NetSentinelAgent"
$taskAction = New-ScheduledTaskAction -Execute $pythonPath -Argument "`"$installDir\agent.py`""
$taskAction.WorkingDirectory = $installDir
$taskTrigger = New-ScheduledTaskTrigger -AtStartup
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Description "NetSentinel Endpoint Security Monitor" -RunLevel Highest | Out-Null
Write-Host "[OK] Scheduled Task 'NetSentinelAgent' created successfully." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 8. Start the Task Immediately
# ---------------------------------------------------------------------------
Write-Host "[+] Starting agent service..." -ForegroundColor Yellow
Start-ScheduledTask -TaskName $taskName
Write-Host "[OK] NetSentinel Agent is now running in the background." -ForegroundColor Green

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  Installation Complete! Agent will phone home shortly." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Read-Host "Press Enter to close this window"