<?php
/**
 * NetSentinel - Devices Management Page
 * Displays all registered endpoint devices with filtering and search capabilities.
 * 
 * SECURITY NOTE: Implements Row-Level Security (RLS) to ensure users only see
 * devices assigned to their group. Admins see all devices.
 */

require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireLogin();

// --- SECURITY: Determine user's access scope ---
$is_admin = (strtolower($_SESSION['role'] ?? '') === 'admin');
$user_group_id = $_SESSION['group_id'] ?? null;

// Build the devices query based on user role
if ($is_admin) {
    // Admins see all devices
    $devices_query = "SELECT * FROM device ORDER BY last_seen_at DESC";
    $stmt = $pdo->query($devices_query);
} else {
    // Standard users only see devices in their group
    if ($user_group_id) {
        $stmt = $pdo->prepare("SELECT * FROM device WHERE device_group_id = ? ORDER BY last_seen_at DESC");
        $stmt->execute([$user_group_id]);
    } else {
        // User has no group - show empty result
        $stmt = $pdo->query("SELECT * FROM device WHERE 1=0");
    }
}

$devices = $stmt->fetchAll(PDO::FETCH_ASSOC);

$page_title = "Endpoint Devices";
require_once __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
    <!-- Page Header -->
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h2 class="mb-0">
                <i class="bi bi-hdd-network me-2"></i>Endpoint Devices
            </h2>
            <p class="text-muted mb-0 mt-1">
                View and manage all monitored devices in your network
            </p>
        </div>
        <div class="d-flex align-items-center gap-3">
            <span class="badge bg-primary fs-6"><?= count($devices) ?> Total Devices</span>
        </div>
    </div>

    <!-- Info Box -->
    <div class="alert alert-info d-flex align-items-center" role="alert">
        <i class="bi bi-info-circle-fill me-3 fs-4"></i>
        <div>
            <strong>What is this page?</strong><br>
            <small>
                This page shows all devices that have been registered with NetSentinel. 
                Each device runs a lightweight agent that periodically checks its security health and reports back to the dashboard.
                <ul class="mb-0 mt-2">
                    <li><span class="badge bg-success">Online</span> = Device reported in the last hour</li>
                    <li><span class="badge bg-warning text-dark">Idle</span> = Device reported in the last 24 hours</li>
                    <li><span class="badge bg-secondary">Offline</span> = No contact for more than 24 hours</li>
                </ul>
            </small>
        </div>
    </div>

    <!-- Devices Table -->
    <div class="card shadow-sm">
        <div class="card-header bg-white py-3">
            <h5 class="mb-0"><i class="bi bi-list-ul me-2"></i>Registered Endpoints</h5>
        </div>
        <div class="card-body p-0">
            <?php if (empty($devices)): ?>
                <div class="text-center py-5">
                    <i class="bi bi-hdd-network display-4 text-muted"></i>
                    <h5 class="mt-3">No Devices Found</h5>
                    <p class="text-muted">
                        <?php if ($is_admin): ?>
                            No devices have been registered yet. Devices will appear here once agents are installed and configured.
                        <?php else: ?>
                            You don't have access to any devices. Contact your administrator to be assigned to a device group.
                        <?php endif; ?>
                    </p>
                </div>
            <?php else: ?>
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0" id="devicesTable">
                        <thead class="table-light">
                            <tr>
                                <th>Hostname</th>
                                <th>OS Family</th>
                                <th>OS Version</th>
                                <th>Last Seen</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($devices as $device): 
                                // Determine status badge
                                $last_seen = strtotime($device['last_seen_at']);
                                $now = time();
                                $hours_since = ($now - $last_seen) / 3600;
                                
                                if ($hours_since < 1) {
                                    $status_badge = '<span class="badge bg-success">Online</span>';
                                } elseif ($hours_since < 24) {
                                    $status_badge = '<span class="badge bg-warning text-dark">Idle</span>';
                                } else {
                                    $status_badge = '<span class="badge bg-secondary">Offline</span>';
                                }
                                
                                // OS Family badge color
                                $os_class = match(strtolower($device['os_family'])) {
                                    'windows' => 'bg-primary',
                                    'linux' => 'bg-success',
                                    'macos' => 'bg-dark',
                                    default => 'bg-secondary'
                                };
                            ?>
                                <tr>
                                    <td class="fw-bold"><?= htmlspecialchars($device['hostname'] ?: 'Unknown') ?></td>
                                    <td><span class="badge <?= $os_class ?>"><?= htmlspecialchars($device['os_family'] ?: 'Unknown') ?></span></td>
                                    <td><code><?= htmlspecialchars($device['os_version'] ?: 'Unknown') ?></code></td>
                                    <td><?= date('d M Y, H:i', strtotime($device['last_seen_at'])) ?></td>
                                    <td><?= $status_badge ?></td>
                                    <td>
                                        <a href="device_detail.php?id=<?= $device['device_id'] ?>" class="btn btn-sm btn-outline-primary">
                                            <i class="bi bi-eye me-1"></i>Details
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
</div>

<!-- DataTables for search/filter -->
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css">

<script>
$(document).ready(function() {
    $('#devicesTable').DataTable({
        pageLength: 10,
        order: [[3, 'desc']], // Sort by Last Seen descending
        language: {
            search: "Filter devices:",
            info: "Showing _START_ to _END_ of _TOTAL_ entries",
            infoEmpty: "No devices available",
            infoFiltered: "(filtered from _MAX_ total entries)"
        }
    });
});
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>