<?php
/**
 * NetSentinel Network Discovery Page
 * Triggers Python ARP/Ping scan via AJAX and displays
 * live results for agent deployment.
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

// Handle Scan Trigger (via AJAX)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['trigger_scan'])) {
    // Return JSON for AJAX requests
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

        // 3. PATHS INSIDE THE DOCKER CONTAINER
        $script_path = '/var/www/scripts/discovery.py';
        $python_path = '/usr/bin/python3';

        // Sanity checks for container environment
        if (!file_exists($script_path) || !file_exists($python_path)) {
            echo json_encode(['success' => false, 'error' => 'CRITICAL: Script or Python not found in container. Check Docker volume mounts.']);
            exit;
        }

        // 4. Execute the command
        // SECURITY (SR3/SR4): CRITICAL - Use escapeshellarg() on the JSON payload.
        // This prevents Command Injection attacks where a malicious user could inject 
        // shell commands (like ; rm -rf /) via the network configuration data.
        $cmd = "$python_path $script_path " . escapeshellarg($networks_json) . " 2>&1";
        
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
            echo json_encode(['success' => false, 'error' => "Discovery script failed (Exit code: $return_var). Output: " . $raw_output]);
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
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>🔍 Network Discovery</h2>
        <button id="runScanBtn" class="btn btn-primary">
            <i class="bi bi-radar"></i> Run ARP/Ping Scan
        </button>
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
        <div class="card-header bg-white">
            <h5 class="mb-0">Discovered Devices</h5>
        </div>
        <div class="card-body">
            <div id="emptyState" class="text-center py-5 text-muted">
                <i class="bi bi-hdd-network display-4"></i>
                <p class="mt-3">No scan results yet. Click "Run ARP/Ping Scan" to discover devices on your configured networks.</p>
            </div>
            
            <div id="resultsContainer" class="d-none">
                <div class="table-responsive">
                    <table id="discoveryTable" class="table table-hover table-striped" style="width:100%">
                        <thead class="table-dark">
                            <tr>
                                <th>IP Address</th>
                                <th>MAC Address</th>
                                <th>Hostname</th>
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

<script>
$(document).ready(function() {
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
            timeout: 60000, // 60 second timeout
            success: function(response) {
                if (response.success) {
                    $statusText.text(response.message);
                    setTimeout(() => $status.addClass('d-none'), 3000);
                    
                    $empty.addClass('d-none');
                    $results.removeClass('d-none');

                    // Destroy existing table if it exists
                    if (discoveryTable) {
                        discoveryTable.clear().destroy();
                    }

                    // Populate table
                    const tbody = $('#discoveryTable tbody');
                    tbody.empty();
                    
                    response.devices.forEach(device => {
                        const row = `
                            <tr>
                                <td><strong>${device.ip}</strong></td>
                                <td><code>${device.mac || 'Unknown'}</code></td>
                                <td>${device.hostname || 'Unknown'}</td>
                                <td>${device.network_name || 'Unknown'}</td>
                                <td>${device.vlan_id || 'N/A'}</td>
                                <td class="text-end">
                                    <button class="btn btn-sm btn-outline-primary" onclick="alert('Agent deployment feature coming in stretch goals!')">
                                        <i class="bi bi-download"></i> Deploy Agent
                                    </button>
                                </td>
                            </tr>
                        `;
                        tbody.append(row);
                    });

                    // Initialize DataTable
                    discoveryTable = $('#discoveryTable').DataTable({
                        order: [[0, 'asc']],
                        pageLength: 10,
                        language: {
                            search: "Filter discovered devices:"
                        }
                    });

                } else {
                    $status.addClass('d-none');
                    $error.removeClass('d-none').text('Error: ' + response.error);
                }
            },
            error: function(xhr, status, error) {
                $status.addClass('d-none');
                $error.removeClass('d-none').text('AJAX Request Failed: ' + error + '. Check console for details.');
            },
            complete: function() {
                $btn.prop('disabled', false).html('<i class="bi bi-radar"></i> Run ARP/Ping Scan');
            }
        });
    });
});
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>