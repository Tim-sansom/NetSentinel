; ============================================================================
; NetSentinel Windows Agent Installer
; Inno Setup Script - Source code for dissertation submission
; Author: Tim Sansom
; Version: 1.0.0
; Date: 2026
; ============================================================================

#define MyAppName "NetSentinel Security Agent"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Tim Sansom - University Dissertation Project"

[Setup]
AppId={{8F3B2A1C-9D4E-4F5A-B6C7-1E2D3C4B5A6F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\NetSentinel
DefaultGroupName=NetSentinel
AllowNoIcons=yes
OutputBaseFilename=NetSentinel_Agent_V1
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64
OutputDir=.\output

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Bundle the PowerShell bootstrap script and core agent files
; We use absolute paths (C:\NetSentinelBuild\) so Inno knows exactly where to look.
Source: "C:\NetSentinelBuild\install_netsentinel.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\NetSentinelBuild\agent.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\NetSentinelBuild\config.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\NetSentinelBuild\README.txt"; DestDir: "{app}"; Flags: isreadme

[Run]
; Execute the PowerShell script. 
; WindowStyle Normal allows the examiner/user to SEE the automation working (builds trust).
; waituntilterminated is CRITICAL so the installer doesn't finish before Python is installed.
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -WindowStyle Normal -File ""{app}\install_netsentinel.ps1"""; Flags: runascurrentuser waituntilterminated

[Code]
// Academic Note: This Pascal script ensures the installer enforces security boundaries
// by verifying administrator privileges before allowing installation.
function InitializeSetup(): Boolean;
begin
  if not IsAdminLoggedOn then
  begin
    MsgBox('This installer requires administrator privileges to install Python and create background services.'#13#10'Please right-click the installer and select "Run as Administrator".', mbError, MB_OK);
    Result := False;
  end
  else
    Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    Log('NetSentinel Agent installed successfully and bootstrap script executed.');
  end;
end;