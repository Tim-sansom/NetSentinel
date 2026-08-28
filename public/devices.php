<?php
/**
 * NetSentinel Devices Page
 * Renders a DataTables view of all registered endpoints
 * with filtering by hostname, OS, and health status.
 */

// Use __DIR__ for consistent path resolution
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

// SECURITY (SR2): Enforce session validation.
requireLogin();

$page_title = "Devices";
require_once __DIR__ . '/includes/header.php';

// Fetch all devices
$devices = [];
$error = '';

try {
    $stmt = $pdo->prepare("
        SELECT device_id, hostname, os_family, os_version, last_seen_at, current_health_status, device_group_id
        FROM device
        ORDER BY last_seen_at DESC
    ");
    $stmt->execute();
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Devices Page Error: " . $e->getMessage());
    $error = "Error fetching devices from the database.";
}
?>

<!-- Page Header -->
<div class="d-flex justify-content-between align-items-center mb-4">
    <div>
        <h2 class="mb-0">
            <i class="bi bi-hdd-network me-2"></i>Endpoint Devices
            <i class="bi bi-question-circle text-muted ms-2" 
               data-bs-toggle="tooltip" 
               data-bs-title="All endpoints registered with NetSentinel monitoring"
               style="cursor: help; font-size: 0.6em; vertical-align: middle;"></i>
        </h2>
        <p class="text-muted mb-0 mt-1">View and manage all monitored devices in your network</p>
    </div>
    <span class="badge bg-primary fs-6"><?= count($devices) ?> Total Devices</span>
</div>

<!-- Info Banner - What is this page? -->
<div class="alert alert-info d-flex align-items-start mb-4" role="alert">
    <i class="bi bi-info-circle-fill me-3 mt-1 fs-5"></i>
    <div>
        <h6 class="alert-heading mb-2">What is this page?</h6>
        <p class="mb-2 small">
            This page shows all devices that have been registered with NetSentinel. Each device runs a lightweight agent 
            that periodically checks its security health and reports back to the dashboard.
        </p>
        <ul class="mb-0 small">
            <li><strong>Online</strong> = Device reported in the last hour</li>
            <li><strong>Idle</strong> = Device reported in the last 24 hours</li>
            <li><strong>Offline</strong> = No contact for more than 24 hours</li>
        </ul>
        <button class="btn btn-sm btn-link p-0 mt-2" type="button" data-bs-toggle="collapse" data-bs-target="#deviceHelp" aria-expanded="false">
            Show more details
        </button>
        <div class="collapse mt-2" id="deviceHelp">
            <div class="card card-body bg-light small">
                <p class="mb-2"><strong>How to use this page:</strong></p>
                <ul class="mb-2">
                    <li>Use the search box to filter devices by hostname or OS</li>
                    <li>Click column headers to sort (e.g., sort by Last Seen to find offline devices)</li>
                    <li>Click "Details" to view a device's full security history and findings</li>
                    <li>If a device shows "Offline", check if the agent is still running on that endpoint</li>
                </ul>
                <p class="mb-0"><strong>Why this matters:</strong> Keeping track of which devices are actively reporting helps you ensure complete network coverage and quickly identify endpoints that may have been disconnected or compromised.</p>
            </div>
        </div>
    </div>
</div>

<?php if ($error): ?>
    <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
<?php endif; ?>

<!-- Devices Table Card -->
<div class="card shadow-sm">
    <div class="card-header bg-white py-3">
        <h5 class="mb-0 text-muted">
            Registered Endpoints
            <i class="bi bi-question-circle text-muted ms-2" 
               data-bs-toggle="tooltip" 
               data-bs-title="Endpoints that have completed the registration process and are sending telemetry data"
               style="cursor: help;"></i>
        </h5>
    </div>
    <div class="card-body">
        <?php if (empty($devices)): ?>
            <div class="text-center py-5">
                <i class="bi bi-hdd-network display-4 text-muted mb-3"></i>
                <p class="text-muted mb-0">No devices registered yet. Deploy an agent or use the Discovery tool to find endpoints.</p>
            </div>
        <?php else: ?>
            <div class="table-responsive">
                <table id="devicesTable" class="table table-hover align-middle mb-0">
                    <thead class="table-light">
                        <tr>
                            <th>
                                Hostname
                                <i class="bi bi-question-circle text-muted ms-1" 
                                   data-bs-toggle="tooltip" 
                                   data-bs-title="The device name on your network. This is automatically detected by the agent."
                                   style="cursor: help;"></i>
                            </th>
                            <th>
                                OS Family
                                <i class="bi bi-question-circle text-muted ms-1" 
                                   data-bs-toggle="tooltip" 
                                   data-bs-title="Operating system type (Windows, Linux, macOS). Helps you identify what platforms are in your environment."
                                   style="cursor: help;"></i>
                            </th>
                            <th>
                                OS Version
                                <i class="bi bi-question-circle text-muted ms-1" 
                                   data-bs-toggle="tooltip" 
                                   data-bs-title="Specific version/build number. Outdated versions may have known security vulnerabilities."
                                   style="cursor: help;"></i>
                            </th>
                            <th>
                                Last Seen
                                <i class="bi bi-question-circle text-muted ms-1" 
                                   data-bs-toggle="tooltip" 
                                   data-bs-title="When the device last reported to NetSentinel. If this is older than 24 hours, the device may be offline or the agent may have stopped running."
                                   style="cursor: help;"></i>
                            </th>
                            <th>
                                Status
                                <i class="bi bi-question-circle text-muted ms-1" 
                                   data-bs-toggle="tooltip" 
                                   data-bs-title="Current connection status based on last check-in time. Online = last hour, Idle = last 24h, Offline = >24h"
                                   style="cursor: help;"></i>
                            </th>
                            <th class="text-end">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($devices as $device): 
                            // Calculate status based on last_seen_at
                            $last_seen_time = strtotime($device['last_seen_at']);
                            $hours_ago = (time() - $last_seen_time) / 3600;
                            
                            if ($hours_ago <= 1) {
                                $status_badge = '<span class="badge bg-success" data-bs-toggle="tooltip" data-bs-title="Device is actively reporting. Last check-in was within the last hour." style="cursor: help;">Online</span>';
                            } elseif ($hours_ago <= 24) {
                                $status_badge = '<span class="badge bg-warning text-dark" data-bs-toggle="tooltip" data-bs-title="Device has not reported recently. Last check-in was between 1-24 hours ago." style="cursor: help;">Idle</span>';
                            } else {
                                $status_badge = '<span class="badge bg-secondary" data-bs-toggle="tooltip" data-bs-title="Device may be offline or agent has stopped. No check-in for more than 24 hours." style="cursor: help;">Offline</span>';
                            }
                            
                            // OS Badge styling
                            $os_badge_class = 'bg-secondary';
                            $os_family_lower = strtolower($device['os_family'] ?? '');
                            if (str_contains($os_family_lower, 'win')) $os_badge_class = 'bg-primary';
                            if (str_contains($os_family_lower, 'linux') || str_contains($os_family_lower, 'ubuntu')) $os_badge_class = 'bg-success';
                            if (str_contains($os_family_lower, 'darwin') || str_contains($os_family_lower, 'mac')) $os_badge_class = 'bg-dark';
                        ?>
                        <tr>
                            <td class="fw-bold"><?= htmlspecialchars($device['hostname'] ?? 'Unknown') ?></td>
                            <td>
                                <span class="badge <?= $os_badge_class ?>"
                                      data-bs-toggle="tooltip" 
                                      data-bs-title="Operating System: <?= htmlspecialchars($device['os_family'] ?? 'Unknown') ?>"
                                      style="cursor: help;">
                                    <?= htmlspecialchars($device['os_family'] ?? 'Unknown') ?>
                                </span>
                            </td>
                            <td><code><?= htmlspecialchars($device['os_version'] ?? 'N/A') ?></code></td>
                            <td><?= date('d M Y, H:i', $last_seen_time) ?></td>
                            <td><?= $status_badge ?></td>
                            <td class="text-end">
                                <a href="device_detail.php?id=<?= urlencode($device['device_id']) ?>" 
                                   class="btn btn-sm btn-outline-primary"
                                   data-bs-toggle="tooltip"
                                   data-bs-title="View detailed security history and findings for this device">
                                    <i class="bi bi-eye"></i> Details
                                </a>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- DataTables Initialization -->
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

    $('#devicesTable').DataTable({
        "paging": true,
        "searching": true,
        "ordering": true,
        "info": true,
        "pageLength": 10,
        "language": {
            "search": "Filter devices:",
            "lengthMenu": "Show _MENU_ entries"
        },
        "columnDefs": [
            { "orderable": false, "targets": 5 } // Disable sorting on the Actions column
        ]
    });
});
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>