<?php
require_once 'includes/db.php';
require_once 'includes/auth.php';

// Ensure user is logged in
requireLogin();

$page_title = "Dashboard Overview";
require_once 'includes/header.php';

// Fetch summary statistics
try {
    // Total devices
    $stmt = $pdo->query("SELECT COUNT(*) as total FROM device");
    $total_devices = $stmt->fetch(PDO::FETCH_ASSOC)['total'];
    
    // Active devices (seen in last 24 hours)
    $stmt = $pdo->query("
        SELECT COUNT(*) as active 
        FROM device 
        WHERE last_seen_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ");
    $active_devices = $stmt->fetch(PDO::FETCH_ASSOC)['active'];
    
    // Devices with critical findings (last 24 hours)
    $stmt = $pdo->query("
        SELECT COUNT(DISTINCT d.device_id) as critical
        FROM device d
        INNER JOIN check_run cr ON d.device_id = cr.device_id
        INNER JOIN port_finding pf ON cr.check_run_id = pf.check_run_id
        WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        AND pf.severity = 'critical'
    ");
    $critical_devices = $stmt->fetch(PDO::FETCH_ASSOC)['critical'];
    
    // Recent alerts (last 7 days)
$stmt = $pdo->query("
    SELECT 
        d.hostname,
        d.device_id,
        'Port' as finding_type,
        CONCAT('Port ', pf.port_number, ' (', COALESCE(pf.process_name, 'Unknown'), ')') as description,
        pf.severity,
        cr.run_timestamp
    FROM port_finding pf
    INNER JOIN check_run cr ON pf.check_run_id = cr.check_run_id
    INNER JOIN device d ON cr.device_id = d.device_id
    WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    AND pf.is_expected = 0
    ORDER BY cr.run_timestamp DESC
    LIMIT 10
");
$recent_alerts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
} catch (PDOException $e) {
    $error = "Error loading dashboard data: " . htmlspecialchars($e->getMessage());
}
?>

<!-- Summary Cards -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card bg-primary text-white h-100">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="card-subtitle mb-2">Total Devices</h6>
                        <h2 class="mb-0"><?= $total_devices ?? 0 ?></h2>
                    </div>
                    <div class="display-4">💻</div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card bg-success text-white h-100">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="card-subtitle mb-2">Active (24h)</h6>
                        <h2 class="mb-0"><?= $active_devices ?? 0 ?></h2>
                    </div>
                    <div class="display-4">✅</div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card bg-danger text-white h-100">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="card-subtitle mb-2">At Risk</h6>
                        <h2 class="mb-0"><?= $critical_devices ?? 0 ?></h2>
                    </div>
                    <div class="display-4">⚠️</div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card bg-info text-white h-100">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="card-subtitle mb-2">Health Score</h6>
                       <h2 class="mb-0">
                        <?php if ($total_devices > 0) {
                            $health = round((($total_devices - $critical_devices) / $total_devices) * 100);
                            echo $health . '%';
                            } 
                            else {
                            echo 'N/A';
                            } ?>
                         </h2>
                    </div>
                    <div class="display-4">📊</div>
                </div>
            </div>
        </div>
    </div>
</div>

<?php if (isset($error)): ?>
    <div class="alert alert-danger"><?= $error ?></div>
<?php endif; ?>

<!-- Recent Alerts -->
<div class="row">
    <div class="col-12">
        <div class="card">
            <div class="card-header bg-warning text-dark">
                <h5 class="mb-0">⚠️ Recent Security Alerts</h5>
            </div>
            <div class="card-body">
                <?php if (empty($recent_alerts)): ?>
                    <p class="text-muted mb-0">No recent alerts found. All systems appear to be secure.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-striped table-hover">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Device</th>
                                    <th>Finding Type</th>
                                    <th>Details</th>
                                    <th>Severity</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($recent_alerts as $alert): ?>
                                    <tr>
                                        <td><?= date('Y-m-d H:i', strtotime($alert['run_timestamp'])) ?></td>
                                        <td>
                                            <a href="device_detail.php?id=<?= htmlspecialchars($alert['device_id']) ?>">
                                                <?= htmlspecialchars($alert['hostname']) ?>
                                            </a>
                                        </td>
                                        <td><?= htmlspecialchars($alert['finding_type']) ?></td>
                                        <td>
                                            <?php if ($alert['port_number']): ?>
                                                Port <?= htmlspecialchars($alert['port_number']) ?>
                                            <?php endif; ?>
                                            <?= htmlspecialchars($alert['description']) ?>
                                        </td>
                                        <td>
                                            <span class="badge bg-<?= $alert['severity'] === 'critical' ? 'danger' : ($alert['severity'] === 'high' ? 'warning' : 'info') ?>">
                                                <?= ucfirst(htmlspecialchars($alert['severity'])) ?>
                                            </span>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
            <div class="card-footer text-end">
                <a href="alerts.php" class="btn btn-sm btn-outline-primary">View All Alerts</a>
            </div>
        </div>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>