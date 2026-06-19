<?php
require_once 'includes/db.php';
require_once 'includes/auth.php';

// Ensure user is logged in
requireLogin();

$page_title = "Devices";
require_once 'includes/header.php';

// Fetch all devices
try {
    $stmt = $pdo->prepare("
        SELECT 
            device_id, 
            hostname, 
            os_family, 
            os_version, 
            last_seen_at,
            current_health_status,
            device_group_id
        FROM device 
        ORDER BY last_seen_at DESC
    ");
    $stmt->execute();
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Error fetching devices: " . htmlspecialchars($e->getMessage());
    $devices = [];
}
?>

<!-- Page Header -->
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2 class="mb-0">Endpoint Devices</h2>
    <span class="badge bg-primary fs-6"><?= count($devices) ?> Total Devices</span>
</div>

<?php if (isset($error)): ?>
    <div class="alert alert-danger"><?= $error ?></div>
<?php endif; ?>

<!-- Devices Table Card -->
<div class="card shadow-sm">
    <div class="card-header bg-white py-3">
        <h5 class="mb-0 text-muted">Registered Endpoints</h5>
    </div>
    <div class="card-body">
        <?php if (empty($devices)): ?>
            <div class="text-center py-5">
                <p class="text-muted mb-0">No devices registered yet. Deploy an agent to start seeing data.</p>
            </div>
        <?php else: ?>
            <div class="table-responsive">
                <table id="devicesTable" class="table table-hover align-middle mb-0">
                    <thead class="table-light">
                        <tr>
                            <th>Hostname</th>
                            <th>OS Family</th>
                            <th>OS Version</th>
                            <th>Last Seen</th>
                            <th>Status</th>
                            <th class="text-end">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($devices as $device): 
                            // Calculate status based on last_seen_at (FIXED)
                            $last_seen_time = strtotime($device['last_seen_at']);
                            $hours_ago = (time() - $last_seen_time) / 3600;
                            
                            if ($hours_ago <= 1) {
                                $status_badge = '<span class="badge bg-success">Online</span>';
                            } elseif ($hours_ago <= 24) {
                                $status_badge = '<span class="badge bg-warning text-dark">Idle</span>';
                            } else {
                                $status_badge = '<span class="badge bg-secondary">Offline</span>';
                            }

                            // OS Badge styling (FIXED - using os_family)
                            $os_badge_class = 'bg-secondary';
                            if (stripos($device['os_family'], 'win') !== false) $os_badge_class = 'bg-primary';
                            if (stripos($device['os_family'], 'linux') !== false || stripos($device['os_family'], 'ubuntu') !== false) $os_badge_class = 'bg-success';
                            
                            // Get device group name
                            $group_name = $device['device_group_id'] ? 'Test Lab' : 'Default';
                        ?>
                            <tr>
                                <td class="fw-bold"><?= htmlspecialchars($device['hostname']) ?></td>
                                <td>
                                    <span class="badge <?= $os_badge_class ?>">
                                        <?= htmlspecialchars($device['os_family']) ?>
                                    </span>
                                </td>
                                <td><code><?= htmlspecialchars($device['os_version']) ?></code></td>
                                <td><?= date('d M Y, H:i', $last_seen_time) ?></td>
                                <td><?= $status_badge ?></td>
                                <td class="text-end">
                                    <a href="device_detail.php?id=<?= urlencode($device['device_id']) ?>" class="btn btn-sm btn-outline-primary">
                                        View Details
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

<!-- DataTables Initialization for this page -->
<script>
    $(document).ready(function() {
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

<?php require_once 'includes/footer.php'; ?>