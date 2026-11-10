<?php
/**
 * NetSentinel - Agent Download & Deployment Page
 * ================================================================================
 *
 * PURPOSE:
 * Provides a centralized, user-friendly hub for downloading and deploying the 
 * NetSentinel endpoint agent across all supported operating systems.
 *
 * UX DESIGN:
 * Vertical stacked layout for optimal readability and balanced visual weight.
 * Each OS gets full-width attention with clear, scannable instructions.
 */

if (session_status() === PHP_SESSION_NONE) { session_start(); }
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$page_title = 'Agent Deployment';
include __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
    <!-- Page Header -->
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h2 class="mb-0"><i class="bi bi-download me-2"></i>Agent Deployment</h2>
            <p class="text-muted mb-0 mt-1">Install the NetSentinel security monitor on your endpoints</p>
        </div>
        <a href="discover.php" class="btn btn-outline-secondary" data-bs-toggle="tooltip" data-bs-title="Return to Network Discovery page">
            <i class="bi bi-arrow-left me-1"></i> Back to Discovery
        </a>
    </div>

    <!-- Introduction / What is the Agent? -->
    <div class="card shadow-sm mb-4 border-0 bg-primary text-white">
        <div class="card-body">
            <h5 class="card-title"><i class="bi bi-info-circle me-2"></i>What is the NetSentinel Agent?</h5>
            <p class="mb-2">The NetSentinel Agent is a lightweight, cross-platform Python script that runs silently in the background on your endpoints. It performs scheduled security-health checks (open ports, firewall status, system metrics) and securely sends the telemetry back to this dashboard.</p>
            <ul class="mb-0 small" style="color: rgba(255,255,255,0.9);">
                <li><strong>Lightweight:</strong> Uses less than 5% CPU and 50MB RAM.</li>
                <li><strong>Secure:</strong> All communication is encrypted via HTTPS with Bearer token authentication.</li>
                <li><strong>Cross-Platform:</strong> Supports Windows, Linux, macOS, and FreeBSD.</li>
            </ul>
        </div>
    </div>

    <!-- WINDOWS - Full Width Card -->
    <div class="card shadow-sm mb-4 border-0 bg-primary text-white" id="windows">
        <div class="card-body">
            <div class="d-flex align-items-center mb-3">
                <i class="bi bi-windows display-4 me-3"></i>
                <div>
                    <h4 class="mb-0">Windows</h4>
                    <small style="color: rgba(255,255,255,0.8);">Windows 10 / 11 (64-bit)</small>
                </div>
            </div>
            
            <p class="mb-3" style="color: rgba(255,255,255,0.9);">
                For system administrators. Deploy instantly using a single PowerShell command. 
                This method bypasses browser download restrictions and uses native Windows package management.
            </p>
            
            <div class="mb-4">
                <label class="form-label small fw-bold" style="color: rgba(255,255,255,0.8);">
                    <i class="bi bi-lightning-fill me-1"></i> Quick Install (One-Liner):
                </label>
                <div class="input-group">
                    <code class="form-control bg-dark text-success font-monospace" id="win-ps-curl" style="font-size: 0.85rem;">
                        irm https://netsentinel.timsansom.co.uk/deploy/install_netsentinel_win.ps1 | iex
                    </code>
                    <button class="btn btn-outline-light" type="button" onclick="copyToClipboard('win-ps-curl', this)" data-bs-toggle="tooltip" data-bs-title="Copy command to clipboard">
                        <i class="bi bi-clipboard"></i>
                    </button>
                </div>
                <small class="text-white-50 mt-1 d-block">
                    <i class="bi bi-shield-check me-1"></i>Run in PowerShell as Administrator
                </small>
            </div>

            <hr class="border-white border-opacity-25">
            
            <div class="mb-3">
                <h6 class="text-white mb-3">
                    <i class="bi bi-folder2-open me-2"></i>Prefer manual offline installation?
                </h6>
                <div class="bg-white bg-opacity-10 rounded p-3 mb-3">
                    <strong>Note:</strong> Browsers may flag the manual ZIP download due to heuristic analysis of unsigned administrative tools. If blocked, use the PowerShell method above, or select "Keep anyway" in your browser's download manager.
                    <ol class="mb-0 mt-2 ps-3 small" style="color: rgba(255,255,255,0.9);">
                        <li>Download and extract the ZIP file below.</li>
                        <li>Right-click <code class="bg-dark bg-opacity-25 text-white px-1">NetSentinel_Agent_V1.exe</code> and select <strong>"Run as Administrator"</strong>.</li>
                        <li>If prompted by Windows Defender, select "More info" → "Run anyway".</li>
                    </ol>
                </div>
                <a href="/deploy/netsentinel_agent_V1.zip" class="btn btn-light text-primary fw-bold w-100" download data-bs-toggle="tooltip" data-bs-title="Download Windows installer package with README">
                    <i class="bi bi-file-zip me-2"></i> Download Manual Package (.zip)
                </a>
            </div>
        </div>
    </div>

    <!-- LINUX - Full Width Card -->
    <div class="card shadow-sm mb-4 border-0 bg-warning text-dark" id="linux">
        <div class="card-body">
            <div class="d-flex align-items-center mb-3">
                <i class="bi bi-ubuntu display-4 me-3"></i>
                <div>
                    <h4 class="mb-0">Linux</h4>
                    <small class="text-dark opacity-75">Debian / Ubuntu / RHEL / CentOS</small>
                </div>
            </div>
            
            <p class="mb-3">
                For system administrators. Deploy instantly across your fleet using a single terminal command. 
                The installer automatically detects your distribution and configures systemd for persistent operation.
            </p>
            
            <div class="mb-4">
                <label class="form-label small fw-bold text-dark opacity-75">
                    <i class="bi bi-lightning-fill me-1"></i> Quick Install (One-Liner):
                </label>
                <div class="input-group">
                    <code class="form-control bg-dark text-success font-monospace" id="linux-curl" style="font-size: 0.85rem;">
                        curl -fsSL https://netsentinel.timsansom.co.uk/deploy/install_netsentinel.sh | sudo bash
                    </code>
                    <button class="btn btn-outline-dark" type="button" onclick="copyToClipboard('linux-curl', this)" data-bs-toggle="tooltip" data-bs-title="Copy command to clipboard">
                        <i class="bi bi-clipboard"></i>
                    </button>
                </div>
                <small class="text-dark opacity-75 mt-1 d-block">
                    <i class="bi bi-terminal me-1"></i>Requires sudo privileges
                </small>
            </div>

            <hr class="border-dark border-opacity-25">
            
            <div class="mb-3">
                <h6 class="text-dark mb-3">
                    <i class="bi bi-folder2-open me-2"></i>Prefer offline installation?
                </h6>
                <div class="bg-white bg-opacity-50 rounded p-3 mb-3">
                    <strong>Manual installation steps:</strong>
                    <ol class="mb-0 mt-2 ps-3 small">
                        <li>Download the tar.gz package below.</li>
                        <li>Extract: <code class="bg-dark bg-opacity-25 text-white px-1">tar -xzf netsentinel-agent-linux.tar.gz</code></li>
                        <li>Navigate to the extracted directory.</li>
                        <li>Run: <code class="bg-dark bg-opacity-25 text-white px-1">sudo ./install_netsentinel.sh</code></li>
                    </ol>
                </div>
                <a href="/deploy/netsentinel-agent-linux.tar.gz" class="btn btn-dark w-100" download data-bs-toggle="tooltip" data-bs-title="Download offline package with full source code">
                    <i class="bi bi-file-zip me-2"></i> Download Offline Package (.tar.gz)
                </a>
            </div>
        </div>
    </div>

    <!-- MACOS - Full Width Card -->
    <div class="card shadow-sm mb-4 border-0 bg-dark text-white" id="macos">
        <div class="card-body">
            <div class="d-flex align-items-center mb-3">
                <i class="bi bi-apple display-4 me-3"></i>
                <div>
                    <h4 class="mb-0">macOS</h4>
                    <small style="color: rgba(255,255,255,0.7);">macOS 12 (Monterey) and later</small>
                </div>
            </div>
            
            <p class="mb-3" style="color: rgba(255,255,255,0.8);">
                For Mac administrators. Installs the agent and configures a launchd plist for automatic startup. 
                Compatible with both Intel and Apple Silicon Macs.
            </p>
            
            <div class="mb-4">
                <label class="form-label small fw-bold" style="color: rgba(255,255,255,0.7);">
                    <i class="bi bi-lightning-fill me-1"></i> Quick Install (One-Liner):
                </label>
                <div class="input-group">
                    <code class="form-control bg-black text-success font-monospace" id="mac-curl" style="font-size: 0.85rem;">
                        curl -fsSL https://netsentinel.timsansom.co.uk/deploy/install_netsentinel_mac.sh | sudo bash
                    </code>
                    <button class="btn btn-outline-light" type="button" onclick="copyToClipboard('mac-curl', this)" data-bs-toggle="tooltip" data-bs-title="Copy command to clipboard">
                        <i class="bi bi-clipboard"></i>
                    </button>
                </div>
                <small class="text-white-50 mt-1 d-block" style="color: rgba(255,255,255,0.7);">
                    <i class="bi bi-terminal me-1"></i>Requires administrator password
                </small>
            </div>

            <hr class="border-white border-opacity-25">
            
            <div class="mb-3">
                <h6 class="text-white mb-3" style="color: rgba(255,255,255,0.7);">
                    <i class="bi bi-folder2-open me-2"></i>Prefer offline installation?
                </h6>
                <div class="bg-white bg-opacity-10 rounded p-3 mb-3">
                    <strong>Manual installation steps:</strong>
                    <ol class="mb-0 mt-2 ps-3 small" style="color: rgba(255,255,255,0.9);">
                        <li>Download the tar.gz package below.</li>
                        <li>Extract: <code class="bg-dark bg-opacity-25 text-white px-1">tar -xzf netsentinel-agent-macos.tar.gz</code></li>
                        <li>Navigate to the extracted directory.</li>
                        <li>Run: <code class="bg-dark bg-opacity-25 text-white px-1">sudo ./install_netsentinel_mac.sh</code></li>
                    </ol>
                </div>
                <a href="/deploy/netsentinel-agent-macos.tar.gz" class="btn btn-outline-light w-100" download data-bs-toggle="tooltip" data-bs-title="Download offline package with full source code">
                    <i class="bi bi-file-zip me-2"></i> Download Offline Package (.tar.gz)
                </a>
            </div>
        </div>
    </div>

    <!-- FREEBSD - Full Width Card -->
    <div class="card shadow-sm mb-4 border-0 bg-secondary text-white" id="freebsd">
        <div class="card-body">
            <div class="d-flex align-items-center mb-3">
                <i class="bi bi-server display-4 me-3"></i>
                <div>
                    <h4 class="mb-0">FreeBSD / Unix</h4>
                    <small style="color: rgba(255,255,255,0.8);">FreeBSD 13+ / Generic Unix</small>
                </div>
            </div>
            
            <p class="mb-3" style="color: rgba(255,255,255,0.9);">
                For traditional Unix environments. Includes rc.d startup script configuration 
                for automatic agent startup on system boot.
            </p>
            
            <div class="bg-white bg-opacity-10 rounded p-3 mb-4">
                <strong>Installation steps:</strong>
                <ol class="mb-0 mt-2 ps-3 small" style="color: rgba(255,255,255,0.9);">
                    <li>Download the shell script below.</li>
                    <li>Make it executable: <code class="bg-dark bg-opacity-25 text-white px-1">chmod +x install_netsentinel_bsd.sh</code></li>
                    <li>Run with root privileges: <code class="bg-dark bg-opacity-25 text-white px-1">sudo ./install_netsentinel_bsd.sh</code></li>
                    <li>The script will install Python dependencies and configure rc.d startup.</li>
                </ol>
            </div>

            <a href="/deploy/install_netsentinel_bsd.sh" class="btn btn-light text-secondary fw-bold w-100" download data-bs-toggle="tooltip" data-bs-title="Download installation shell script">
                <i class="bi bi-file-code me-2"></i> Download Install Script (.sh)
            </a>
            
            <div class="mt-3">
                <a href="/deploy/netsentinel-agent-bsd.tar.gz" class="btn btn-outline-light w-100" download data-bs-toggle="tooltip" data-bs-title="Download complete offline package">
                    <i class="bi bi-file-zip me-2"></i> Download Complete Package (.tar.gz)
                </a>
            </div>
        </div>
    </div>

</div>

<!-- Clipboard Copy Script -->
<script>
function copyToClipboard(elementId, btnElement) {
    const text = document.getElementById(elementId).innerText;
    navigator.clipboard.writeText(text).then(() => {
        // Visual feedback
        const originalIcon = btnElement.innerHTML;
        btnElement.innerHTML = '<i class="bi bi-check-lg"></i>';
        btnElement.classList.remove('btn-outline-light', 'btn-outline-dark');
        btnElement.classList.add('btn-success');
        
        setTimeout(() => {
            btnElement.innerHTML = originalIcon;
            btnElement.classList.remove('btn-success');
            if (btnElement.closest('.bg-primary') || btnElement.closest('.bg-dark')) {
                btnElement.classList.add('btn-outline-light');
            } else {
                btnElement.classList.add('btn-outline-dark');
            }
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy: ', err);
    });
}
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>