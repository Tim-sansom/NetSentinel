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

$page_title = 'Network Discovery';
$message = '';
$message_type = '';

// Handle "Add This Machine" (localhost registration)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_localhost'])) {
    try {
        // Generate unique device UUID and API token
        $device_uuid = 'localhost-' . bin2hex(random_bytes(4));
        $api_token = 'NetSentinel_' . bin2hex(random_bytes(16));
        $token_hash = hash('sha256', $api_token);
        
        // Get server hostname and OS details
        $hostname = gethostname() ?: 'localhost';
        $os_family = php_uname('s');
        $os_version = php_uname('r');
        
        // Insert device into database
        $stmt = $pdo->prepare("
            INSERT INTO device 
            (device_uuid, hostname, ip_address, os_family, os_version, token_hash, is_active, created_at)
            VALUES (?, ?, '127.0.0.1', ?, ?, ?, 1, NOW())
        ");
        $stmt->execute([$device_uuid, $hostname, $os_family, $os_version, $token_hash]);
        
        // SECURITY (SR4): Log the administrative action
        require_once __DIR__ . '/includes/audit.php';
        log_audit($pdo, $_SESSION['user_id'], 'DEVICE_ADDED_LOCALHOST', 'device', $pdo->lastInsertId());
        
        $message = "Localhost registered successfully! Device UUID: <code>$device_uuid</code>";
        $message_type = 'success';
        
        // Store token in session for immediate display
        $_SESSION['localhost_token'] = $api_token;
        $_SESSION['localhost_uuid'] = $device_uuid;
        
    } catch (PDOException $e) {
        $message = 'Error registering localhost: ' . htmlspecialchars($e->getMessage());
        $message_type = 'danger';
    }
}

// Handle Scan Trigger (via AJAX)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['trigger_scan'])) {
    header('Content-Type: application/json');
    
    try {
        // 1. Fetch configured networks from DB
        $stmt = $pdo->query("SELECT cidr, name, vlan_id FROM networks");
        $networks = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        if (empty($networks)) {
            echo json_encode(['success' => false, 'error' => 'No networks configured. Please add a network in Network Management first.']);
            exit;
        }

        // 2. Prepare JSON payload
        $networks_json = json_encode($networks);

        // 3. PATHS INSIDE THE DOCKER CONTAINER (Matches docker-compose.yml volumes)
        $script_path = '/var/www/scripts/discovery.py';
        $python_path = '/usr/bin/python3';

        if (!file_exists($script_path) || !file_exists($python_path)) {
            echo json_encode(['success' => false, 'error' => 'CRITICAL: Script or Python not found in container.']);
            exit;
        }

        // 4. Execute the command
        // SECURITY (SR3): CRITICAL - Use escapeshellarg() to prevent Command Injection attacks.
        // We omit '2>&1' to prevent Python debug output from corrupting the JSON response.
        $cmd = "$python_path $script_path " . escapeshellarg($networks_json);
        
        $output = [];
        $return_var = 0;
        exec($cmd, $output, $return_var);
        $raw_output = implode("\n", $output);

        if ($return_var === 0) {
            $result = json_decode($raw_output, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($result)) {
                echo json_encode([
                    'success' => true,
                    'message' => "Scan completed. Found " . count($result) . " devices.",
                    'devices' => $result
                ]);
            } else {
                echo json_encode(['success' => false, 'error' => "Failed to parse Python output: " . $raw_output]);
            }
        } else {
            echo json_encode(['success' => false, 'error' => "Discovery script failed (Exit code: $return_var)."]);
        }
    } catch (PDOException $e) {
        error_log("Discovery DB Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => "Database error."]);
    }
    exit; // Important: exit after JSON response to prevent HTML leakage
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
            <!-- FIXED: Removed data-bs-toggle="tooltip" to prevent conflict with modal. Initialized via JS below. -->
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

    <!-- Info Banner - What is this page? -->
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
                                <th>
                                    IP Address
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The network address of the discovered device."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    MAC Address
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The unique hardware identifier. 'unknown' means the scan couldn't retrieve it."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    Hostname
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The device name on the network. 'unknown' means DNS resolution failed."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    Device Type
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="Detected operating system based on network TTL values and hostname heuristics."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    Network Name
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The name of the subnet this device was found on, as configured in Network Management."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    VLAN
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The Virtual LAN ID associated with this network segment, if configured."
                                       style="cursor: help;"></i>
                                </th>
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
                        git clone https://github.com/yourusername/netsentinel-agent.git<br>
                        cd netsentinel-agent
                    </code>
                </div>

                <h6 class="mb-3">2. Configure the Agent</h6>
                <div class="mb-3">
                    <p class="small text-muted">Create or edit <code>config.py</code>:</p>
                    <pre class="bg-dark text-light p-3 rounded"><code>API_URL = "https://<?= $_SERVER['HTTP_HOST'] ?>/api/submit.php"
DEVICE_UUID = "<?= htmlspecialchars($_SESSION['localhost_uuid']) ?>"
API_TOKEN = "<?= htmlspecialchars($_SESSION['localhost_token']) ?>"
CHECK_INTERVAL = 300  # 5 minutes
ENABLE_LOG_CHECK = true
ENABLE_PORT_CHECK = true
ENABLE_FIREWALL_CHECK = true</code></pre>
                </div>

                <h6 class="mb-3">3. Install Dependencies</h6>
                <div class="mb-3">
                    <code class="d-block p-2 bg-light border rounded">
                        pip install requests psutil schedule
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

    // FIXED: Initialize tooltip for Add This Machine button specifically 
    // to avoid conflict with data-bs-toggle="modal"
    var addMachineBtn = document.getElementById('addThisMachineBtn');
    if (addMachineBtn) {
        new bootstrap.Tooltip(addMachineBtn, {
            title: 'Instantly register this server for quick testing without network scanning',
            placement: 'bottom',
            trigger: 'hover'
        });
    }

    let discoveryTable = null;

    $('#runScanBtn').on('click', function() {
        const $btn = $(this);
        const $status = $('#scanStatus');
        const $statusText = $('#scanStatusText');
        const $error = $('#scanError');
        const $empty = $('#emptyState');
        const $results = $('#resultsContainer');

        // Reset UI
        $error.addClass('d-none').text('');
        $status.removeClass('d-none');
        $statusText.text('Scanning configured networks... This may take up to 30 seconds.');
        $btn.prop('disabled', true).html('<span class="spinner-border spinner-border-sm me-2"></span>Scanning...');

        // Send AJAX request
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
                    
                    // Re-initialize tooltips for dynamically added rows
                    var newTooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
                    newTooltipTriggerList.map(function (tooltipTriggerEl) {
                        return new bootstrap.Tooltip(tooltipTriggerEl, {
                            trigger: 'hover',
                            placement: 'auto'
                        })
                    });

                } else {
                    $status.addClass('d-none');
                    $error.removeClass('d-none').text('Error: ' + response.error);
                }
            },
            error: function(xhr, status, error) {
                $status.addClass('d-none');
                $error.removeClass('d-none').text('AJAX Request Failed: ' + error);
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