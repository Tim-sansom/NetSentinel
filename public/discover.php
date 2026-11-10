<?php
/**
 * NetSentinel - Network Discovery Page
 * ================================================================================
 *
 * PURPOSE:
 * Provides network scanning capabilities to discover unmanaged devices on configured
 * subnets. Triggers an adaptive Python-based scanner via AJAX and displays results
 * in real-time without page reloads.
 *
 * ACADEMIC SIGNIFICANCE:
 * This module demonstrates several advanced web application concepts:
 * 1. Asynchronous Execution (NFR1): Non-blocking UI via AJAX for long-running tasks.
 * 2. Historical Delta Tracking: Algorithmically comparing scan snapshots to identify
 *    newly connected devices, a critical feature for SME security monitoring.
 * 3. Strict Row-Level Security (SR2): Ensuring multi-tenant isolation at every query level.
 *
 * SECURITY BOUNDARIES:
 * - SR2 (Access Control): All database queries are strictly filtered by `user_id` or `device_group_id`.
 * - SR3 (Input Sanitisation): Uses `escapeshellarg()` to prevent command injection when passing
 *   JSON payloads to the underlying OS shell.
 *
 * @author Tim Sansom
 * @version 1.0
 * @date 2026
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';

// Redirect unauthenticated users
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// ===========================================================================
// ROLE AND SCOPE DETERMINATION (SR2)
// ===========================================================================
// Normalize role to lowercase to prevent case-sensitivity bypasses
$current_role = strtolower($_SESSION['role'] ?? '');
$is_super_admin = ($current_role === 'super_admin');
$current_user_id = $_SESSION['user_id'];
$user_group_id = $_SESSION['group_id'] ?? null;

// ===========================================================================
// AJAX HANDLER 1: TRIGGER NEW NETWORK SCAN
// ===========================================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['trigger_scan'])) {
    // Clear output buffers to ensure a clean JSON response
    while (ob_get_level()) { ob_end_clean(); }
    header('Content-Type: application/json');
    
    try {
        // STEP 1: Fetch networks with STRICT Row-Level Security (RLS)
        if ($is_super_admin) {
            $stmt = $pdo->query("SELECT network_id, cidr, name, vlan_id FROM networks");
        } else {
            if ($user_group_id === null) {
                echo json_encode(['success' => false, 'error' => 'Account not assigned to a group.']);
                exit(0);
            }
            // Standard admins can ONLY scan networks belonging to their tenant group
            $stmt = $pdo->prepare("SELECT network_id, cidr, name, vlan_id FROM networks WHERE device_group_id = ?");
            $stmt->execute([$user_group_id]);
        }
        $networks = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        if (empty($networks)) { 
            echo json_encode(['success' => false, 'error' => 'No networks configured for your group.']); 
            exit(0); 
        }

        // STEP 2: Create audit record for the scan session
        $stmt = $pdo->prepare("INSERT INTO network_scan (user_id, networks_scanned, status) VALUES (?, ?, 'running')");
        $stmt->execute([$current_user_id, count($networks)]);
        $scan_id = $pdo->lastInsertId();

        // STEP 3: Execute Adaptive Python Script
        $script_path = __DIR__ . '/../scripts/discovery.py';
        $python_path = '/usr/bin/python3';
        $networks_json = json_encode($networks);

        // SR3: escapeshellarg() is critical here to prevent OS command injection
        $cmd = "$python_path $script_path " . escapeshellarg($networks_json);
        $output = []; 
        $return_var = 0;
        exec($cmd, $output, $return_var);
        $raw_output = implode("\n", $output);

        // STEP 4: Process and persist results
        if ($return_var === 0) {
            $result = json_decode($raw_output, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($result)) {
                $devices_saved = 0;
                foreach ($result as $device) {
                    $vlan_val = $device['vlan_id'] ?? null;
                    if ($vlan_val === 'N/A' || !is_numeric($vlan_val)) $vlan_val = null;
                    
                    $insert_stmt = $pdo->prepare("
                        INSERT INTO network_scan_result 
                        (scan_id, ip_address, mac_address, hostname, device_type, network_name, vlan_id, first_seen, last_seen, is_active) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), 1)
                    ");
                    if ($insert_stmt->execute([
                        $scan_id, $device['ip'] ?? '', $device['mac'] ?? 'unknown', 
                        $device['hostname'] ?? 'unknown', $device['device_type'] ?? 'Unknown', 
                        $device['network_name'] ?? 'Unknown', $vlan_val
                    ])) {
                        $devices_saved++;
                    }
                }

                // Update scan session status to completed
                $pdo->prepare("UPDATE network_scan SET status = 'completed', scan_completed = NOW(), devices_found = ? WHERE scan_id = ?")
                    ->execute([$devices_saved, $scan_id]);
                
                echo json_encode([
                    'success' => true, 
                    'message' => "Scan completed. Found {$devices_saved} devices.", 
                    'devices' => $result, 
                    'scan_id' => $scan_id
                ]);
                exit(0);
            }
        }
        
        // Handle script failure
        echo json_encode([
            'success' => false, 
            'error' => "Script failed (Exit code: $return_var).", 
            'output' => substr($raw_output, 0, 500)
        ]);
        
    } catch (PDOException $e) {
        error_log("Discovery DB Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => "Database error: " . $e->getMessage()]);
    }
    exit(0);
}

// ===========================================================================
// AJAX HANDLER 2: FETCH HISTORICAL SCAN RESULTS (WITH DELTA TRACKING)
// ===========================================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['fetch_scan_id'])) {
    header('Content-Type: application/json');
    $target_scan_id = (int)$_POST['fetch_scan_id'];

    try {
        // SR2: Verify the requested scan actually belongs to the current user
        $check_sql = "SELECT scan_id FROM network_scan WHERE scan_id = ?";
        $check_params = [$target_scan_id];
        if (!$is_super_admin) {
            $check_sql .= " AND user_id = ?";
            $check_params[] = $current_user_id;
        }
        $check_stmt = $pdo->prepare($check_sql);
        $check_stmt->execute($check_params);
        
        if (!$check_stmt->fetch()) {
            echo json_encode(['success' => false, 'error' => 'Access denied or scan not found.']);
            exit(0);
        }

        // DELTA TRACKING ALGORITHM: Find the immediately preceding scan for this user
        $prev_sql = "SELECT scan_id FROM network_scan WHERE scan_id < ?";
        $prev_params = [$target_scan_id];
        if (!$is_super_admin) {
            $prev_sql .= " AND user_id = ?";
            $prev_params[] = $current_user_id;
        }
        $prev_sql .= " ORDER BY scan_id DESC LIMIT 1";
        
        $prev_stmt = $pdo->prepare($prev_sql);
        $prev_stmt->execute($prev_params);
        $prev_scan = $prev_stmt->fetch(PDO::FETCH_ASSOC);
        $prev_scan_id = $prev_scan ? $prev_scan['scan_id'] : null;

        // Extract all IP addresses from the previous scan for comparison
        $prev_ips = [];
        if ($prev_scan_id) {
            $ip_stmt = $pdo->prepare("SELECT ip_address FROM network_scan_result WHERE scan_id = ?");
            $ip_stmt->execute([$prev_scan_id]);
            $prev_ips = array_column($ip_stmt->fetchAll(PDO::FETCH_ASSOC), 'ip_address');
        }

        // Fetch full results for the target scan
        $res_stmt = $pdo->prepare("SELECT * FROM network_scan_result WHERE scan_id = ? ORDER BY ip_address");
        $res_stmt->execute([$target_scan_id]);
        $results = $res_stmt->fetchAll(PDO::FETCH_ASSOC);

        // Flag "NEW" devices (IPs present in current scan but absent in previous scan)
        foreach ($results as &$row) {
            $row['is_new'] = !in_array($row['ip_address'], $prev_ips);
        }

        echo json_encode(['success' => true, 'results' => $results, 'scan_id' => $target_scan_id]);
        exit(0);

    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'error' => "Database error: " . $e->getMessage()]);
    }
    exit(0);
}

// ===========================================================================
// PAGE RENDERING
// ===========================================================================
$page_title = 'Network Discovery';

// Fetch scan history with STRICT RLS.
// Ordered ASC (oldest first) to ensure the per-user counter (#1, #2, #3) is logical.
if ($is_super_admin) {
    $scan_history_query = "
        SELECT ns.scan_id, ns.scan_started, ns.scan_completed, ns.networks_scanned, ns.devices_found, ns.status 
        FROM network_scan ns 
        ORDER BY ns.scan_started ASC
    ";
    $scan_history = $pdo->query($scan_history_query)->fetchAll(PDO::FETCH_ASSOC);
} else {
    $scan_history_query = "
        SELECT ns.scan_id, ns.scan_started, ns.scan_completed, ns.networks_scanned, ns.devices_found, ns.status 
        FROM network_scan ns 
        WHERE ns.user_id = ? 
        ORDER BY ns.scan_started ASC
    ";
    $stmt = $pdo->prepare($scan_history_query);
    $stmt->execute([$current_user_id]);
    $scan_history = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

include __DIR__ . '/includes/header.php';
?>

<!-- ========================================================================= -->
<!-- HTML CONTENT - NETWORK DISCOVERY INTERFACE -->
<!-- ========================================================================= -->

<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h2 class="mb-0"><i class="bi bi-search me-2"></i>Network Discovery</h2>
            <p class="text-muted mb-0 mt-1">Adaptive scanning with historical delta tracking</p>
        </div>
        
        <!-- UPDATED: Clean, simple button linking to the dedicated download page -->
        <div class="d-flex gap-2" role="group" aria-label="Discovery and Deployment Actions">
            <button id="runScanBtn" class="btn btn-primary" data-bs-toggle="tooltip" data-bs-title="Start a new network discovery scan">
                <i class="bi bi-radar me-1"></i> Run New Scan
            </button>
            <a href="download.php" class="btn btn-success" data-bs-toggle="tooltip" data-bs-title="View all deployment options and instructions">
                <i class="bi bi-download me-1"></i> Deploy Agent
            </a>
        </div>
    </div>

    <div class="alert alert-info d-flex align-items-start mb-4" role="alert">
        <i class="bi bi-info-circle-fill me-3 mt-1 fs-5"></i>
        <div>
            <h6 class="alert-heading mb-2">How It Works</h6>
            <p class="mb-0 small">Click on any row in the <strong>Scan History</strong> below to view the exact results of that scan. Devices highlighted in <span class="badge bg-success">NEW</span> did not exist in your previous scan, helping you track network growth.</p>
        </div>
    </div>

    <!-- Scan History Table -->
    <div class="card shadow-sm mb-4">
        <div class="card-header bg-white py-3">
            <h5 class="mb-0 text-muted"><i class="bi bi-clock-history me-2"></i>Scan History (Click a row to view results)</h5>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-sm table-hover" id="scanHistoryTable" style="width:100%">
                    <thead class="table-dark">
                        <tr><th>Scan #</th><th>Started</th><th>Completed</th><th>Networks</th><th>Devices Found</th><th>Status</th></tr>
                    </thead>
                    <tbody>
                        <?php if (empty($scan_history)): ?>
                        <tr><td colspan="6" class="text-center text-muted py-3">No scan history found.</td></tr>
                        <?php else: ?>
                            <?php 
                            $user_scan_counter = 1;
                            foreach ($scan_history as $scan): 
                            ?>
                            <tr style="cursor: pointer;" data-scan-id="<?= (int)$scan['scan_id'] ?>" title="Click to view results for Scan #<?= $user_scan_counter ?>">
                                <td>#<?= $user_scan_counter ?></td>
                                <td><?= date('d M Y, H:i', strtotime($scan['scan_started'])) ?></td>
                                <td><?= $scan['scan_completed'] ? date('H:i', strtotime($scan['scan_completed'])) : '<span class="text-muted">In Progress</span>' ?></td>
                                <td><?= (int)$scan['networks_scanned'] ?></td>
                                <td><?= (int)$scan['devices_found'] ?></td>
                                <td>
                                    <?php $badge_class = ['running' => 'bg-primary', 'completed' => 'bg-success', 'failed' => 'bg-danger'][$scan['status']] ?? 'bg-secondary'; ?>
                                    <span class="badge <?= $badge_class ?>"><?= ucfirst($scan['status']) ?></span>
                                </td>
                            </tr>
                            <?php 
                            $user_scan_counter++;
                            endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Dynamic UI States -->
    <div id="scanStatus" class="alert alert-info d-none" role="alert">
        <div class="d-flex align-items-center">
            <div class="spinner-border spinner-border-sm me-2" role="status"></div>
            <span id="scanStatusText">Loading scan results...</span>
        </div>
    </div>
    <div id="scanError" class="alert alert-danger d-none" role="alert"></div>

    <!-- Discovered Devices Results -->
    <div class="card shadow-sm">
        <div class="card-header bg-white py-3"><h5 class="mb-0 text-muted">Scan Results</h5></div>
        <div class="card-body">
            <div id="emptyState" class="text-center py-5 text-muted">
                <i class="bi bi-hdd-network display-4"></i>
                <p class="mt-3">Select a scan from the history above, or run a new scan to see results.</p>
            </div>
            <div id="noResultsState" class="text-center py-5 text-muted d-none">
                <i class="bi bi-search display-4"></i>
                <p class="mt-3">This scan completed but found no devices.</p>
            </div>
            <div id="resultsContainer" class="d-none">
                <div class="table-responsive">
                    <table id="discoveryTable" class="table table-hover table-striped" style="width:100%">
                        <thead class="table-dark">
                            <tr><th>IP Address</th><th>MAC Address</th><th>Hostname</th><th>Device Type</th><th>Network Name</th><th>VLAN</th><th class="text-end">Actions</th></tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- ========================================================================= -->
<!-- JAVASCRIPT - AJAX SCAN FUNCTIONALITY AND DELTA TRACKING UI -->
<!-- ========================================================================= -->
<script>
$(document).ready(function() {
    let historyTable = null;
    let discoveryTable = null;

    // Initialize Bootstrap Tooltips for all elements with data-bs-toggle="tooltip"
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            trigger: 'hover',
            placement: 'auto'
        });
    });

    // Initialize History Table (Ascending order to match PHP counter)
    if ($('#scanHistoryTable').length > 0) {
        historyTable = $('#scanHistoryTable').DataTable({ 
            order: [[0, 'asc']],  
            pageLength: 10, 
            language: { search: "Filter scan history:" }, 
            destroy: true 
        });
    }

    // =========================================================================
    // EVENT: Load Historical Scan Results (Delta Tracking UI)
    // =========================================================================
    $('#scanHistoryTable tbody').on('click', 'tr', function() {
        let scanId = $(this).data('scan-id');
        if (!scanId) return;

        // Highlight selected row for UX
        $('#scanHistoryTable tbody tr').removeClass('table-active');
        $(this).addClass('table-active');

        // Show loading state
        $('#emptyState, #noResultsState, #resultsContainer').addClass('d-none');
        $('#scanStatus').removeClass('d-none');
        $('#scanStatusText').text(`Loading historical data for Scan #${scanId}...`);

        $.ajax({
            url: 'discover.php',
            type: 'POST',
            data: { fetch_scan_id: scanId },
            dataType: 'json',
            success: function(response) {
                $('#scanStatus').addClass('d-none');
                
                if (response.success && response.results && response.results.length > 0) {
                    $('#resultsContainer').removeClass('d-none');
                    
                    if (discoveryTable) discoveryTable.clear().destroy();
                    const tbody = $('#discoveryTable tbody');
                    tbody.empty();

                    // Render rows, applying Delta Tracking visual cues
                    response.results.forEach(device => {
                        let rowClass = device.is_new ? 'table-success' : '';
                        let newBadge = device.is_new ? '<span class="badge bg-success ms-2">NEW</span>' : '';

                        // SMART ANCHORING LOGIC: Detect OS and link directly to the correct section
                        let deviceType = (device.device_type || '').toLowerCase();
                        let anchor = '';

                        if (deviceType.includes('windows')) {
                            anchor = '#windows';
                        } else if (deviceType.includes('linux') || deviceType.includes('pi') || deviceType.includes('debian')) {
                            anchor = '#linux';
                        } else if (deviceType.includes('mac') || deviceType.includes('apple')) {
                            anchor = '#macos';
                        } else if (deviceType.includes('freebsd') || deviceType.includes('unix')) {
                            anchor = '#freebsd';
                        }

                        let deployBtn = `<a href="download.php${anchor}" class="btn btn-sm btn-outline-primary" data-bs-toggle="tooltip" data-bs-title="View deployment options for ${device.device_type || 'this device'}">
                                            <i class="bi bi-download me-1"></i> Deploy
                                         </a>`;

                        tbody.append(`<tr class="${rowClass}">
                            <td><strong>${device.ip_address}</strong>${newBadge}</td>
                            <td><code>${device.mac_address || 'unknown'}</code></td>
                            <td>${device.hostname || 'unknown'}</td>
                            <td>${device.device_type || 'Unknown'}</td>
                            <td>${device.network_name || 'Unknown'}</td>
                            <td>${device.vlan_id || 'N/A'}</td>
                            <td class="text-end">${deployBtn}</td>
                        </tr>`);
                    });

                    discoveryTable = $('#discoveryTable').DataTable({ 
                        order: [[0, 'asc']], 
                        pageLength: 25,
                        destroy: true 
                    });
                    
                    // CRITICAL: Re-initialize Bootstrap Tooltips for dynamically created content
                    var newTooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
                    newTooltipTriggerList.map(function (tooltipTriggerEl) {
                        return new bootstrap.Tooltip(tooltipTriggerEl, {
                            trigger: 'hover',
                            placement: 'auto'
                        });
                    });
                    
                    console.log('✅ Re-initialized Bootstrap tooltips for dynamic content');
                } else if (response.success) {
                    $('#noResultsState').removeClass('d-none');
                } else {
                    $('#scanError').removeClass('d-none').text(response.error || 'Failed to load results');
                }
            },
            error: function(xhr, status, error) {
                console.error('AJAX Error:', status, error, xhr.responseText);
                $('#scanStatus').addClass('d-none');
                $('#scanError').removeClass('d-none').text('Failed to load scan results. Check browser console.');
            }
        });
    });

    // =========================================================================
    // EVENT: Run New Scan
    // =========================================================================
    $('#runScanBtn').on('click', function() {
        const $btn = $(this);
        const $status = $('#scanStatus');
        const $statusText = $('#scanStatusText');
        const $error = $('#scanError');

        $error.addClass('d-none').text('');
        $status.removeClass('d-none');
        $statusText.text('Running new adaptive scan... This may take up to 30 seconds.');
        $btn.prop('disabled', true).html('<span class="spinner-border spinner-border-sm me-2"></span>Scanning...');

        $.ajax({
            url: 'discover.php', 
            type: 'POST', 
            data: { trigger_scan: true }, 
            dataType: 'json', 
            timeout: 60000,
            success: function(response) {
                if (response.success) {
                    window.location.reload();
                } else {
                    $status.addClass('d-none');
                    $error.removeClass('d-none').html('Error: ' + response.error);
                }
            },
            error: function(xhr, status, error) { 
                $status.addClass('d-none'); 
                $error.removeClass('d-none').text('AJAX Request Failed: ' + error); 
            },
            complete: function() { 
                $btn.prop('disabled', false).html('<i class="bi bi-radar me-1"></i> Run New Scan'); 
            }
        });
    });
});
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>