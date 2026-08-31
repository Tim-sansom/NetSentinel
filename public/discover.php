<?php
/**
 * NetSentinel Network Discovery Page
 * Triggers Python ARP/Ping scan via AJAX and displays
 * live results for agent deployment. Also allows quick 
 * registration of localhost for immediate testing.
 * 
 * This page demonstrates secure asynchronous operations (NFR1) using AJAX 
 * to prevent UI blocking during network scans, and strict input validation 
 * (SR3) when executing system commands via escapeshellarg().
 * 
 * SECURITY NOTE: Implements Row-Level Security (RLS) to ensure standard 
 * users only see scan history for their own account.
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';

// SECURITY (SR2): Ensure user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// --- SECURITY: Determine user's access scope ---
$is_admin = (strtolower($_SESSION['role'] ?? '') === 'admin');
$current_user_id = $_SESSION['user_id'];
$user_group_id = $_SESSION['group_id'] ?? null;

// === AJAX HANDLER: Must be at the very top, before any HTML ===
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['trigger_scan'])) {
    
    // DEBUG: Initialize log file ONLY when a scan is triggered
    $debug_file = '/tmp/discovery_debug.log';
    file_put_contents($debug_file, 
        "\n\n=== SCAN STARTED: " . date('Y-m-d H:i:s') . " ===\n", 
        FILE_APPEND
    );

    // Disable any output buffering issues
    while (ob_get_level()) {
        ob_end_clean();
    }
    
    header('Content-Type: application/json');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    
    try {
        // 1. Fetch configured networks
        $stmt = $pdo->query("SELECT network_id, cidr, name, vlan_id FROM networks");
        $networks = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        if (empty($networks)) {
            echo json_encode(['success' => false, 'error' => 'No networks configured.']);
            exit(0);
        }

        // 2. Create scan session (tied to current user)
        $stmt = $pdo->prepare("INSERT INTO network_scan (user_id, networks_scanned, status) VALUES (?, ?, 'running')");
        $stmt->execute([$current_user_id, count($networks)]);
        $scan_id = $pdo->lastInsertId();
        
        file_put_contents($debug_file, "Created scan session ID: $scan_id for user: $current_user_id\n", FILE_APPEND);

        // 3. Execute Python script
        $script_path = '/var/www/scripts/discovery.py';
        $python_path = '/usr/bin/python3';
        $networks_json = json_encode($networks);

        if (!file_exists($script_path) || !file_exists($python_path)) {
            $pdo->prepare("UPDATE network_scan SET status = 'failed' WHERE scan_id = ?")->execute([$scan_id]);
            echo json_encode(['success' => false, 'error' => 'Script or Python not found.']);
            exit(0);
        }

        $cmd = "$python_path $script_path " . escapeshellarg($networks_json);
        $output = [];
        $return_var = 0;
        exec($cmd, $output, $return_var);
        $raw_output = implode("\n", $output);
        
        file_put_contents($debug_file, "Python script exit code: $return_var\n", FILE_APPEND);

        if ($return_var === 0) {
            $result = json_decode($raw_output, true);
            
            if (json_last_error() === JSON_ERROR_NONE && is_array($result)) {
                file_put_contents($debug_file, "Successfully parsed " . count($result) . " devices from Python.\n", FILE_APPEND);
                
                // 4. SAVE TO DATABASE
                $devices_saved = 0;
                foreach ($result as $device) {
                    try {
                        $vlan_val = $device['vlan_id'] ?? null;
                        if ($vlan_val === 'N/A' || !is_numeric($vlan_val)) {
                            $vlan_val = null;
                        }
                        
                        $insert_stmt = $pdo->prepare("
                            INSERT INTO network_scan_result 
                            (scan_id, ip_address, mac_address, hostname, device_type, network_name, vlan_id, first_seen, last_seen, is_active) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), 1)
                        ");
                        
                        $success = $insert_stmt->execute([
                            $scan_id,
                            $device['ip'] ?? '',
                            $device['mac'] ?? 'unknown',
                            $device['hostname'] ?? 'unknown',
                            $device['device_type'] ?? 'Unknown',
                            $device['network_name'] ?? 'Unknown',
                            $vlan_val
                        ]);
                        
                        if ($success) {
                            $devices_saved++;
                        }
                    } catch (PDOException $e) {
                        file_put_contents($debug_file, "✗ PDO ERROR: " . $e->getMessage() . "\n", FILE_APPEND);
                    }
                }

                // 5. Update scan session
                $pdo->prepare("UPDATE network_scan SET status = 'completed', scan_completed = NOW(), devices_found = ? WHERE scan_id = ?")
                    ->execute([$devices_saved, $scan_id]);

                // 6. Return JSON
                echo json_encode([
                    'success' => true,
                    'message' => "Scan completed. Found and saved {$devices_saved} devices.",
                    'devices' => $result,
                    'scan_id' => $scan_id
                ]);
                exit(0);
            } else {
                $pdo->prepare("UPDATE network_scan SET status = 'failed' WHERE scan_id = ?")->execute([$scan_id]);
                echo json_encode([
                    'success' => false, 
                    'error' => "Failed to parse Python output.",
                    'raw_output' => substr($raw_output, 0, 500)
                ]);
                exit(0);
            }
        } else {
            $pdo->prepare("UPDATE network_scan SET status = 'failed' WHERE scan_id = ?")->execute([$scan_id]);
            echo json_encode([
                'success' => false, 
                'error' => "Script failed (Exit code: $return_var).",
                'output' => substr($raw_output, 0, 500)
            ]);
            exit(0);
        }
    } catch (PDOException $e) {
        error_log("Discovery DB Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => "Database error: " . $e->getMessage()]);
        exit(0);
    }
}

// === REGULAR PAGE RENDERING ===
$page_title = 'Network Discovery';
$message = '';
$message_type = '';

// Handle "Add This Machine" (localhost registration)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_localhost'])) {
    try {
        $device_uuid = 'localhost-' . bin2hex(random_bytes(4));
        $api_token = 'NetSentinel_' . bin2hex(random_bytes(16));
        $token_hash = hash('sha256', $api_token);
        $hostname = gethostname() ?: 'localhost';
        $os_family = php_uname('s');
        $os_version = php_uname('r');
        
        // SECURITY: Assign the new localhost device to the user's group (if they have one)
        $stmt = $pdo->prepare("
            INSERT INTO device 
            (device_uuid, hostname, ip_address, os_family, os_version, token_hash, device_group_id, is_active, created_at)
            VALUES (?, ?, '127.0.0.1', ?, ?, ?, ?, 1, NOW())
        ");
        $stmt->execute([$device_uuid, $hostname, $os_family, $os_version, $token_hash, $user_group_id]);
        
        require_once __DIR__ . '/includes/audit.php';
        log_audit($pdo, $current_user_id, 'DEVICE_ADDED_LOCALHOST', 'device', $pdo->lastInsertId());
        
        $message = "Localhost registered successfully! Device UUID: <code>$device_uuid</code>";
        $message_type = 'success';
        $_SESSION['localhost_token'] = $api_token;
        $_SESSION['localhost_uuid'] = $device_uuid;
        
    } catch (PDOException $e) {
        $message = 'Error registering localhost: ' . htmlspecialchars($e->getMessage());
        $message_type = 'danger';
    }
}

// --- SECURITY: Fetch Scan History with Row-Level Security ---
if ($is_admin) {
    // Admins see all scan history
    $scan_history_query = "
        SELECT ns.*, u.username
        FROM network_scan ns
        LEFT JOIN user u ON ns.user_id = u.user_id
        ORDER BY ns.scan_started DESC
    ";
    $scan_history = $pdo->query($scan_history_query)->fetchAll(PDO::FETCH_ASSOC);
} else {
    // Standard users ONLY see their own scan history
    $scan_history_query = "
        SELECT ns.*, u.username
        FROM network_scan ns
        LEFT JOIN user u ON ns.user_id = u.user_id
        WHERE ns.user_id = ?
        ORDER BY ns.scan_started DESC
    ";
    $stmt = $pdo->prepare($scan_history_query);
    $stmt->execute([$current_user_id]);
    $scan_history = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

include __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
    <!-- Page Header -->
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h2 class="mb-0">
                <i class="bi bi-search me-2"></i>Network Discovery
                <i class="bi bi-question-circle text-muted ms-2" 
                   data-bs-toggle="tooltip" 
                   data-bs-title="Identify unmanaged devices on your network and register them for monitoring"
                   style="cursor: help; font-size: 0.6em; vertical-align: middle;"></i>
            </h2>
            <p class="text-muted mb-0 mt-1">Scan your local network or instantly register this server for testing</p>
        </div>
        <div>
            <button class="btn btn-success me-2" id="addThisMachineBtn" data-bs-toggle="modal" data-bs-target="#localhostModal">
                <i class="bi bi-plus-circle me-1"></i> Add This Machine
            </button>
            <button id="runScanBtn" class="btn btn-primary"
                    data-bs-toggle="tooltip" 
                    data-bs-title="Scan configured subnets to discover active devices on your network">
                <i class="bi bi-radar me-1"></i> Run ARP/Ping Scan
            </button>
        </div>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-<?= $message_type ?> alert-dismissible fade show" role="alert">
            <?= $message ?>
            <?php if (isset($_SESSION['localhost_token'])): ?>
                <button type="button" class="btn btn-sm btn-outline-primary ms-3" data-bs-toggle="modal" data-bs-target="#agentConfigModal"
                        data-bs-toggle="tooltip" 
                        data-bs-title="View configuration details for the newly registered device">
                    <i class="bi bi-download me-1"></i> Get Agent Config
                </button>
            <?php endif; ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>

    <!-- Info Banner -->
    <div class="alert alert-info d-flex align-items-start mb-4" role="alert">
        <i class="bi bi-info-circle-fill me-3 mt-1 fs-5"></i>
        <div>
            <h6 class="alert-heading mb-2">What is Network Discovery?</h6>
            <p class="mb-2 small">
                This tool helps you find devices on your local network that are not yet monitored by NetSentinel. 
                You have two options to get started:
            </p>
            <ul class="mb-0 small">
                <li><strong>Add This Machine:</strong> Instantly registers the server you are currently using. Perfect for testing the full monitoring pipeline in under 2 minutes without scanning.</li>
                <li><strong>Run ARP/Ping Scan:</strong> Scans the subnets you configured in <a href="networks.php" class="alert-link">Network Management</a> to find active endpoints.</li>
            </ul>
            <button class="btn btn-sm btn-link p-0 mt-2" type="button" data-bs-toggle="collapse" data-bs-target="#discoveryHelp" aria-expanded="false"
                    data-bs-toggle="tooltip" data-bs-title="Expand to see how to interpret scan results">
                Show how to interpret results
            </button>
            <div class="collapse mt-2" id="discoveryHelp">
                <div class="card card-body bg-light small">
                    <p class="mb-2"><strong>Understanding the scan results:</strong></p>
                    <ul class="mb-2">
                        <li><strong>IP Address:</strong> The network location of the discovered device.</li>
                        <li><strong>MAC Address:</strong> The unique hardware identifier. If this shows "unknown", it usually means the scan couldn't retrieve it (common in Docker bridge environments).</li>
                        <li><strong>Hostname:</strong> The device name on the network. "unknown" means reverse DNS resolution failed.</li>
                        <li><strong>Device Type:</strong> The detected operating system (Windows, Linux/Unix, Network Device) based on network TTL values and hostname heuristics.</li>
                        <li><strong>Actions:</strong> Click "Deploy Agent" to get the configuration needed to install the NetSentinel agent on that specific device.</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <!-- Scan History -->
    <div class="card shadow-sm mb-4">
        <div class="card-header bg-white py-3">
            <h5 class="mb-0 text-muted">
                <i class="bi bi-clock-history me-2"></i>Recent Scan History
            </h5>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-sm table-hover" id="scanHistoryTable" style="width:100%">
                    <thead>
                        <tr>
                            <th>Scan ID</th>
                            <th>Started</th>
                            <th>Completed</th>
                            <th>Networks</th>
                            <th>Devices Found</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($scan_history)): ?>
                            <tr>
                                <td colspan="6" class="text-center text-muted py-3">No scan history found.</td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($scan_history as $scan): ?>
                            <tr>
                                <td data-order="<?= $scan['scan_id'] ?>">#<?= $scan['scan_id'] ?></td>
                                <td><?= date('d M Y, H:i', strtotime($scan['scan_started'])) ?></td>
                                <td><?= $scan['scan_completed'] ? date('H:i', strtotime($scan['scan_completed'])) : 'In Progress' ?></td>
                                <td><?= $scan['networks_scanned'] ?></td>
                                <td><?= $scan['devices_found'] ?></td>
                                <td>
                                    <?php
                                    $badge_class = [
                                        'running' => 'bg-primary',
                                        'completed' => 'bg-success',
                                        'failed' => 'bg-danger'
                                    ][$scan['status']] ?? 'bg-secondary';
                                    ?>
                                    <span class="badge <?= $badge_class ?>"><?= ucfirst($scan['status']) ?></span>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Scan Status / Loading Spinner -->
    <div id="scanStatus" class="alert alert-info d-none" role="alert">
        <div class="d-flex align-items-center">
            <div class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></div>
            <span id="scanStatusText">Scanning configured networks... This may take up to 30 seconds.</span>
        </div>
    </div>

    <!-- Error Alert -->
    <div id="scanError" class="alert alert-danger d-none" role="alert"></div>

    <!-- Results Table -->
    <div class="card shadow-sm">
        <div class="card-header bg-white py-3">
            <h5 class="mb-0 text-muted">
                Discovered Devices
                <i class="bi bi-question-circle text-muted ms-2" 
                   data-bs-toggle="tooltip" 
                   data-bs-title="Endpoints found during the most recent network scan"
                   style="cursor: help;"></i>
            </h5>
        </div>
        <div class="card-body">
            <div id="emptyState" class="text-center py-5 text-muted">
                <i class="bi bi-hdd-network display-4"></i>
                <p class="mt-3">No scan results yet. Click "Run ARP/Ping Scan" to discover devices on your configured networks, or use "Add This Machine" to start testing immediately.</p>
            </div>
            
            <div id="resultsContainer" class="d-none">
                <div class="table-responsive">
                    <table id="discoveryTable" class="table table-hover table-striped" style="width:100%">
                        <thead class="table-dark">
                            <tr>
                                <th>IP Address</th>
                                <th>MAC Address</th>
                                <th>Hostname</th>
                                <th>Device Type</th>
                                <th>Network Name</th>
                                <th>VLAN</th>
                                <th class="text-end">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Populated by JS -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Add Localhost Modal -->
<div class="modal fade" id="localhostModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="POST" action="discover.php">
            <input type="hidden" name="add_localhost" value="1">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-plus-circle text-success me-2"></i> Add This Machine</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p>Register this server (<code><?= gethostname() ?: 'localhost' ?></code>) immediately for testing without network scanning.</p>
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle me-2"></i> This will:
                        <ul class="mb-0 mt-2">
                            <li>Create a device entry for 127.0.0.1</li>
                            <li>Generate a unique API token</li>
                            <li>Provide instant agent configuration</li>
                        </ul>
                    </div>
                    <p class="text-muted small mb-0">Perfect for testing the full monitoring pipeline in under 2 minutes!</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-success">Register Localhost</button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Agent Configuration Modal -->
<?php if (isset($_SESSION['localhost_token'])): ?>
<div class="modal fade" id="agentConfigModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><i class="bi bi-download me-2"></i> Agent Configuration</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="alert alert-success">
                    <strong>Device Registered!</strong> Use the configuration below to deploy the agent.
                </div>
                
                <h6 class="mb-3">1. Download the Agent</h6>
                <div class="mb-3">
                    <code class="d-block p-2 bg-light border rounded">
                        git clone https://github.com/Tim-sansom/NetSentinel.git<br>
                        cd NetSentinel/agent
                    </code>
                </div>

                <h6 class="mb-3">2. Configure the Agent</h6>
                <div class="mb-3">
                    <p class="small text-muted">Create or edit <code>.env</code> in the agent directory:</p>
                    <pre class="bg-dark text-light p-3 rounded"><code>NETSENTINEL_API_URL="https://<?= $_SERVER['HTTP_HOST'] ?>/api/submit.php"
NETSENTINEL_DEVICE_UUID="<?= htmlspecialchars($_SESSION['localhost_uuid']) ?>"
NETSENTINEL_API_TOKEN="<?= htmlspecialchars($_SESSION['localhost_token']) ?>"
NETSENTINEL_CHECK_INTERVAL=300</code></pre>
                </div>

                <h6 class="mb-3">3. Install Dependencies</h6>
                <div class="mb-3">
                    <code class="d-block p-2 bg-light border rounded">
                        pip install -r requirements.txt
                    </code>
                </div>

                <h6 class="mb-3">4. Run the Agent</h6>
                <div class="mb-3">
                    <code class="d-block p-2 bg-light border rounded">
                        python agent.py
                    </code>
                </div>

                <div class="alert alert-warning">
                    <i class="bi bi-exclamation-triangle me-2"></i> 
                    <strong>Important:</strong> For production, run as a service using systemd (Linux) or Task Scheduler (Windows).
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <a href="devices.php" class="btn btn-primary">View Dashboard</a>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<script>
$(document).ready(function() {
    // Initialize Bootstrap Tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            trigger: 'hover',
            placement: 'auto'
        })
    })

    var addMachineBtn = document.getElementById('addThisMachineBtn');
    if (addMachineBtn) {
        new bootstrap.Tooltip(addMachineBtn, {
            title: 'Instantly register this server for quick testing without network scanning',
            placement: 'bottom',
            trigger: 'hover'
        });
    }

    // Initialize DataTables for both tables
    let historyTable = null;
    let discoveryTable = null;

    // 1. Initialize Scan History Table with Pagination
    if ($('#scanHistoryTable').length > 0) {
        historyTable = $('#scanHistoryTable').DataTable({
            order: [[0, 'desc']], // Sort by Scan ID descending
            pageLength: 10,       // Show 10 results per page
            language: {
                search: "Filter scan history:",
                emptyTable: "No scans have been run yet."
            }
        });
    }

    $('#runScanBtn').on('click', function() {
        const $btn = $(this);
        const $status = $('#scanStatus');
        const $statusText = $('#scanStatusText');
        const $error = $('#scanError');
        const $empty = $('#emptyState');
        const $results = $('#resultsContainer');

        $error.addClass('d-none').text('');
        $status.removeClass('d-none');
        $statusText.text('Scanning configured networks... This may take up to 30 seconds.');
        $btn.prop('disabled', true).html('<span class="spinner-border spinner-border-sm me-2"></span>Scanning...');

        $.ajax({
            url: 'discover.php',
            type: 'POST',
            data: { trigger_scan: true },
            dataType: 'json',
            timeout: 60000,
            success: function(response) {
                if (response.success) {
                    $statusText.text(response.message);
                    setTimeout(() => $status.addClass('d-none'), 3000);
                    
                    $empty.addClass('d-none');
                    $results.removeClass('d-none');

                    if (discoveryTable) {
                        discoveryTable.clear().destroy();
                    }

                    const tbody = $('#discoveryTable tbody');
                    tbody.empty();
                    
                    response.devices.forEach(device => {
                        const row = `
                            <tr>
                                <td><strong>${device.ip}</strong></td>
                                <td><code>${device.mac || 'unknown'}</code></td>
                                <td>${device.hostname || 'unknown'}</td>
                                <td>${device.device_type || 'Unknown'}</td>
                                <td>${device.network_name || 'Unknown'}</td>
                                <td>${device.vlan_id || 'N/A'}</td>
                                <td class="text-end">
                                    <button class="btn btn-sm btn-outline-primary" 
                                            data-bs-toggle="tooltip" 
                                            data-bs-title="Click to get deployment instructions for ${device.ip}"
                                            onclick="showDeployAgentModal('${device.ip}')">
                                        <i class="bi bi-download me-1"></i> Deploy Agent
                                    </button>
                                </td>
                            </tr>
                        `;
                        tbody.append(row);
                    });

                    discoveryTable = $('#discoveryTable').DataTable({
                        order: [[0, 'asc']],
                        pageLength: 10,
                        language: {
                            search: "Filter discovered devices:"
                        }
                    });
                    
                    var newTooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
                    newTooltipTriggerList.map(function (tooltipTriggerEl) {
                        return new bootstrap.Tooltip(tooltipTriggerEl, {
                            trigger: 'hover',
                            placement: 'auto'
                        })
                    });

                    // 2. Update Scan History Table dynamically using DataTables API
                    const now = new Date();
                    const dateStr = now.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
                    const timeStr = now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
                    
                    const historyRow = `
                        <tr>
                            <td data-order="${response.scan_id}">#${response.scan_id}</td>
                            <td>${dateStr}, ${timeStr}</td>
                            <td>${timeStr}</td>
                            <td>1</td>
                            <td>${response.devices.length}</td>
                            <td><span class="badge bg-success">Completed</span></td>
                        </tr>
                    `;
                    
                    if (historyTable) {
                        historyTable.row.add($(historyRow)).draw();
                    }

                } else {
                    $status.addClass('d-none');
                    let errorMsg = response.error;
                    if (response.raw_output || response.output) {
                        errorMsg += "<br><small class='text-muted'>Debug: " + (response.raw_output || response.output) + "</small>";
                    }
                    $error.removeClass('d-none').html('Error: ' + errorMsg);
                }
            },
            error: function(xhr, status, error) {
                $status.addClass('d-none');
                $error.removeClass('d-none').text('AJAX Request Failed: ' + error);
                console.error('AJAX Error:', xhr.responseText);
            },
            complete: function() {
                $btn.prop('disabled', false).html('<i class="bi bi-radar me-1"></i> Run ARP/Ping Scan');
            }
        });
    });
});

function showDeployAgentModal(ip) {
    alert('Agent deployment for ' + ip + ' will be implemented in stretch goals. For now, manually deploy using the agent installer.');
}
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>