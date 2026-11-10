# ==============================================================================
# NetSentinel Windows Agent - Zero-Touch Deployment Script (Production Ready)
# Author: Tim Sansom (University Dissertation Project)
# ==============================================================================

# 1. Enforce Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[!] CRITICAL ERROR: This script must be run as Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  NetSentinel Windows Agent Installer (Zero-Touch)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$installDir = "C:\Program Files\NetSentinel"
$deployUrl = "https://netsentinel.timsansom.co.uk/deploy"
# FIXED: Added /api to the base URL so the agent points to the correct endpoint
$apiUrl = "https://netsentinel.timsansom.co.uk/api" 

# 2. Create Installation Directory
Write-Host "`n[+] Preparing installation directory..." -ForegroundColor Yellow
if (!(Test-Path $installDir)) {
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
}

# 3. Download, Extract, and FLATTEN Agent Source Code
Write-Host "[+] Downloading full agent package from server..." -ForegroundColor Yellow
$zipUrl = "$deployUrl/netsentinel-agent-source.zip"
$tempZipPath = "$env:TEMP\netsentinel-agent-source.zip"
$tempExtractPath = "$env:TEMP\netsentinel-extract"

try {
    Invoke-WebRequest -Uri $zipUrl -OutFile $tempZipPath -UseBasicParsing
    if (Test-Path $tempExtractPath) { Remove-Item -Recurse -Force $tempExtractPath }
    Expand-Archive -Path $tempZipPath -DestinationPath $tempExtractPath -Force
    
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

# 4. Find or Install Real Python (Ignoring Windows Store Stub)
$pythonPath = $null
$knownPaths = @(
    "C:\Program Files\Python311\python.exe",
    "C:\Program Files\Python310\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe"
)

foreach ($path in $knownPaths) {
    if (Test-Path $path) { $pythonPath = $path; break }
}

if (-not $pythonPath) {
    $realPythons = Get-Command python.exe -All -ErrorAction SilentlyContinue | Where-Object { $_.Source -notlike "*WindowsApps*" }
    if ($realPythons) { $pythonPath = $realPythons[0].Source }
}

if (-not $pythonPath) {
    Write-Host "[!] Python not found. Installing via Windows Package Manager (winget)..." -ForegroundColor Yellow
    try {
        winget install Python.Python.3.11 --scope machine --accept-package-agreements --accept-source-agreements --silent
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        foreach ($path in $knownPaths) {
            if (Test-Path $path) { $pythonPath = $path; break }
        }
        if (-not $pythonPath) {
            $realPythons = Get-Command python.exe -All -ErrorAction SilentlyContinue | Where-Object { $_.Source -notlike "*WindowsApps*" }
            if ($realPythons) { $pythonPath = $realPythons[0].Source }
        }
    } catch {
        Write-Host "[!] ERROR: Winget installation failed." -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

if (-not $pythonPath) {
    Write-Host "[!] CRITICAL ERROR: Could not locate a valid Python installation." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "[OK] Using real Python at: $pythonPath" -ForegroundColor Green

# 5. Ensure pip is installed and Install Dependencies
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

# 6. Generate Configuration (.env)
Write-Host "[+] Generating secure configuration (.env)..." -ForegroundColor Yellow
$uuid = [guid]::NewGuid().ToString()
$token = [guid]::NewGuid().ToString()

$envContent = @"
NETSENTINEL_API_URL=$apiUrl
NETSENTINEL_API_TOKEN=$token
NETSENTINEL_DEVICE_UUID=$uuid
CHECK_INTERVAL=300
"@

Set-Content -Path "$installDir\.env" -Value $envContent -Force
Write-Host "[OK] Configuration generated with unique Device UUID and API Token." -ForegroundColor Green

# 7. Create Scheduled Task for Persistence
Write-Host "[+] Configuring Windows Scheduled Task..." -ForegroundColor Yellow
$taskName = "NetSentinelAgent"

$taskAction = New-ScheduledTaskAction -Execute $pythonPath -Argument "`"$installDir\agent.py`""
$taskAction.WorkingDirectory = $installDir 

$taskTrigger = New-ScheduledTaskTrigger -AtStartup
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Description "NetSentinel Endpoint Security Monitor" -RunLevel Highest | Out-Null
Write-Host "[OK] Scheduled Task 'NetSentinelAgent' created successfully." -ForegroundColor Green

# 8. Start the Task Immediately
Write-Host "[+] Starting agent service..." -ForegroundColor Yellow
Start-ScheduledTask -TaskName $taskName
Write-Host "[OK] NetSentinel Agent is now running in the background." -ForegroundColor Green

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  Installation Complete! Agent will phone home shortly." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Read-Host "Press Enter to close this window"