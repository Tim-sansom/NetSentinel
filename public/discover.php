<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Basic auth check
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';

// Ensure user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$page_title = 'Network Discovery';
$discovered_devices = [];
$scan_message = '';
$scan_error = '';

// Handle Scan Trigger (via AJAX)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['trigger_scan'])) {
    // Return JSON for AJAX requests
    header('Content-Type: application/json');
    
    try {
        // 1. Fetch configured networks from DB
        $stmt = $pdo->query("SELECT cidr, name, vlan_id FROM networks");
        $networks = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        if (empty($networks)) {
            echo json_encode([
                'success' => false,
                'error' => 'No networks configured. Please add networks in Network Settings first.'
            ]);
            exit;
        }
        
        // 2. Prepare JSON payload
        $networks_json = json_encode($networks);
        
        // 3. PATHS INSIDE THE DOCKER CONTAINER
        $script_path = '/var/www/scripts/discovery.py';
        $python_path = '/usr/bin/python3'; 
        
        // Debug checks
        if (!file_exists($script_path)) {
            echo json_encode([
                'success' => false,
                'error' => "CRITICAL: Script not found at $script_path inside the container."
            ]);
            exit;
        } elseif (!file_exists($python_path)) {
            echo json_encode([
                'success' => false,
                'error' => "CRITICAL: Python not found at $python_path inside the container."
            ]);
            exit;
        }
        
        // 4. Execute the command
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
                    'message' => "Scan completed successfully. Found " . count($result) . " devices.",
                    'devices' => $result
                ]);
            } else {
                echo json_encode([
                    'success' => false,
                    'error' => "Failed to parse Python output: " . $raw_output
                ]);
            }
        } else {
            echo json_encode([
                'success' => false,
                'error' => "Discovery script failed (Exit code: $return_var): " . $raw_output
            ]);
        }
    } catch (PDOException $e) {
        echo json_encode([
            'success' => false,
            'error' => "Database error: " . $e->getMessage()
        ]);
    }
    exit; // Important: exit after JSON response
}

include __DIR__ . '/includes/header.php';
?>

<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2>🔍 Network Discovery</h2>
        <button type="button" id="scanButton" class="btn btn-primary">
            <i class="bi bi-radar"></i> Run ARP/Ping Scan
        </button>
    </div>

    <!-- Scanning Progress Indicator (Hidden by default) -->
    <div id="scanProgress" class="d-none text-center my-4 p-4 bg-dark border border-secondary rounded">
        <div class="spinner-border text-primary" role="status" style="width: 3rem; height: 3rem;">
            <span class="visually-hidden">Loading...</span>
        </div>
        <h5 class="mt-3 text-light">Scanning Network...</h5>
        <p class="text-muted">Querying devices and resolving hostnames. This may take 30-60 seconds.</p>
        <!-- Animated progress bar -->
        <div class="progress mt-3" style="height: 10px; max-width: 400px; margin: 10px auto;">
            <div class="progress-bar progress-bar-striped progress-bar-animated bg-primary" role="progressbar" style="width: 100%"></div>
        </div>
    </div>

    <!-- Results Container -->
    <div id="scanResults"></div>
</div>

<script>
$(document).ready(function() {
    // Scan button click handler
    $('#scanButton').on('click', function() {
        // Show progress indicator
        $('#scanProgress').removeClass('d-none');
        $('#scanButton').prop('disabled', true).html('<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Scanning...');
        $('#scanResults').html(''); // Clear previous results
        
        // Send AJAX request
        $.ajax({
            url: 'discover.php',
            type: 'POST',
            data: { trigger_scan: 1 },
            dataType: 'json',
            timeout: 120000, // 2 minute timeout
            success: function(response) {
                // Hide progress indicator
                $('#scanProgress').addClass('d-none');
                $('#scanButton').prop('disabled', false).html('<i class="bi bi-radar"></i> Run ARP/Ping Scan');
                
                if (response.success) {
                    // Show success message
                    $('#scanResults').html(`
                        <div class="alert alert-success alert-dismissible fade show" role="alert">
                            ${response.message}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                        ${renderDevicesTable(response.devices)}
                    `);
                    
                    // Initialize DataTable
                    $('#discoveryTable').DataTable({
                        order: [[0, 'asc'], [2, 'asc']],
                        pageLength: 25,
                        language: {
                            search: "Filter discovered devices:"
                        }
                    });
                    
                    // Attach deploy button handlers
                    $('.deploy-agent-btn').on('click', function() {
                        const ip = $(this).data('ip');
                        const mac = $(this).data('mac');
                        alert('Deployment logic for ' + ip + ' (MAC: ' + mac + ') will be implemented in the next phase.');
                    });
                } else {
                    // Show error
                    $('#scanResults').html(`
                        <div class="alert alert-danger alert-dismissible fade show" role="alert">
                            ${response.error}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    `);
                }
            },
            error: function(xhr, status, error) {
                // Hide progress indicator
                $('#scanProgress').addClass('d-none');
                $('#scanButton').prop('disabled', false).html('<i class="bi bi-radar"></i> Run ARP/Ping Scan');
                
                // Show error
                $('#scanResults').html(`
                    <div class="alert alert-danger alert-dismissible fade show" role="alert">
                        <strong>AJAX Error:</strong> ${status} - ${error}<br>
                        <small>Response: ${xhr.responseText}</small>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                `);
            }
        });
    });
    
    // Helper function to render devices table
    function renderDevicesTable(devices) {
        if (!devices || devices.length === 0) {
            return '<div class="alert alert-info">No devices discovered.</div>';
        }
        
        let rows = '';
        devices.forEach(device => {
            const mac = device.mac || 'unknown';
            const network = device.network_name || 'Unknown';
            const vlan = device.vlan_id || 'N/A';
            const hostname = device.hostname || 'unknown';
            
            rows += `
                <tr>
                    <td>${device.ip}</td>
                    <td><code>${mac}</code></td>
                    <td>${network}</td>
                    <td>${vlan}</td>
                    <td>${hostname}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-success deploy-agent-btn" 
                                data-ip="${device.ip}"
                                data-mac="${mac}">
                            Deploy Agent
                        </button>
                    </td>
                </tr>
            `;
        });
        
        return `
            <div class="card bg-dark text-light border-secondary">
                <div class="card-body">
                    <h5 class="card-title">Discovered Devices</h5>
                    <p class="card-text text-muted">Devices that responded to ICMP and were found in the local ARP table.</p>
                    
                    <div class="table-responsive">
                        <table class="table table-hover table-dark" id="discoveryTable" style="width:100%">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>MAC Address</th>
                                    <th>Network</th>
                                    <th>VLAN</th>
                                    <th>Hostname</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${rows}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    }
});
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>