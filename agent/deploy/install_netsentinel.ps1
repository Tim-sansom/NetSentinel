# NetSentinel Windows Bootstrap Installer
# Installs Python, dependencies, and configures a background Scheduled Task.

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  NetSentinel Windows Agent Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 1. Check for Admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Error: Please run this script as Administrator." -ForegroundColor Red
    exit 1
}

# 2. Check/Install Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if ($pythonCmd -and $pythonCmd.Source -notlike "*WindowsApps*") {
    Write-Host "[OK] Python detected: $(& python --version)" -ForegroundColor Green
} else {
    Write-Host "[!] Python not found. Installing via winget..." -ForegroundColor Yellow
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install Python.Python.3.11 --accept-package-agreements --accept-source-agreements
    } else {
        Write-Host "[!] winget not found. Downloading Python installer..." -ForegroundColor Red
        $url = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
        $out = "$env:TEMP\python_installer.exe"
        Invoke-WebRequest -Uri $url -OutFile $out
        Start-Process -FilePath $out -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait
    }
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}

# 3. Setup Directory & Install Dependencies
$installDir = "C:\NetSentinel"
if (!(Test-Path $installDir)) { New-Item -ItemType Directory -Force -Path $installDir | Out-Null }

Write-Host "[+] Installing Python dependencies (requests, psutil)..." -ForegroundColor Cyan
& pip install requests psutil --quiet

# 4. Create Scheduled Task for Auto-Start (Runs as SYSTEM on boot)
$taskName = "NetSentinelAgent"
schtasks /query /tn $taskName > $null 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Updating existing Scheduled Task..." -ForegroundColor Yellow
    schtasks /delete /tn $taskName /f
}

$action = New-ScheduledTaskAction -Execute "python.exe" -Argument "$installDir\agent.py" -WorkingDirectory $installDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description "NetSentinel Endpoint Security Agent" | Out-Null
Start-ScheduledTask -TaskName $taskName

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Agent is running in the background as '$taskName'."
Write-Host "Next: Copy 'agent.py' and 'config.py' to $installDir and configure your API Token."
pause