<?php
require_once 'includes/db.php';
require_once 'includes/auth.php';

// Ensure user is logged in
requireLogin();

$page_title = "Recent Alerts";
require_once 'includes/header.php';

try {
    // 1. Fetch Summary Counts for the top cards
    // Only count from port_finding which has 'severity' column
    $stmt = $pdo->query("
        SELECT 
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count
        FROM port_finding
    ");
    $counts = $stmt->fetch(PDO::FETCH_ASSOC);

    // 2. Fetch the main alerts feed
    // ONLY include port_finding and firewall_finding. 
    // system_finding is removed because it stores metadata (OS info), not security alerts.
    $stmt = $pdo->query("
        SELECT 
            c.run_timestamp,
            d.hostname,
            d.device_id,
            'Port' AS finding_type,
            CONCAT('Port ', p.port_number, ' (', COALESCE(p.process_name, 'Unknown'), ')') AS detail,
            p.severity,
            p.is_expected
        FROM port_finding p
        JOIN check_run c ON p.check_run_id = c.check_run_id
        JOIN device d ON c.device_id = d.device_id

        UNION ALL

        SELECT 
            c.run_timestamp,
            d.hostname,
            d.device_id,
            'Firewall' AS finding_type,
            CONCAT('Profile: ', COALESCE(f.profile, 'Unknown'), ' | Risky Rules: ', f.risky_rule_count) AS detail,
            CASE WHEN f.status = 'Warning' THEN 'high' ELSE 'info' END AS severity,
            NULL AS is_expected
        FROM firewall_finding f
        JOIN check_run c ON f.check_run_id = c.check_run_id
        JOIN device d ON c.device_id = d.device_id

        ORDER BY run_timestamp DESC
        LIMIT 500
    ");
    $alerts = $stmt->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    $error = "Database error: " . htmlspecialchars($e->getMessage());
    $alerts = [];
    $counts = ['critical_count' => 0, 'high_count' => 0, 'medium_count' => 0];
}
?>

<!-- Page Header -->
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2 class="mb-0">🚨 Security Alerts Feed</h2>
    <span class="badge bg-primary fs-6"><?= count($alerts) ?> Recent Findings</span>
</div>

<?php if (isset($error)): ?>
    <div class="alert alert-danger"><?= $error ?></div>
<?php endif; ?>

<!-- Summary Cards -->
<div class="row mb-4">
    <div class="col-md-4">
        <div class="card border-danger border-start border-4 shadow-sm">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="text-muted mb-1">Critical Alerts</h6>
                        <h3 class="mb-0 text-danger"><?= $counts['critical_count'] ?? 0 ?></h3>
                    </div>
                    <div class="display-6 text-danger opacity-50">🔥</div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card border-warning border-start border-4 shadow-sm">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="text-muted mb-1">High Severity</h6>
                        <h3 class="mb-0 text-warning"><?= $counts['high_count'] ?? 0 ?></h3>
                    </div>
                    <div class="display-6 text-warning opacity-50">⚠️</div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card border-info border-start border-4 shadow-sm">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="text-muted mb-1">Medium / Info</h6>
                        <h3 class="mb-0 text-info"><?= $counts['medium_count'] ?? 0 ?></h3>
                    </div>
                    <div class="display-6 text-info opacity-50">ℹ️</div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Alerts Table Card -->
<div class="card shadow-sm">
    <div class="card-header bg-white py-3">
        <h5 class="mb-0 text-muted">Global Findings Timeline</h5>
    </div>
    <div class="card-body">
        <?php if (empty($alerts)): ?>
            <div class="text-center py-5">
                <p class="text-muted mb-0">No security alerts found. Your endpoints are looking clean!</p>
            </div>
        <?php else: ?>
            <div class="table-responsive">
                <table id="alertsTable" class="table table-hover align-middle mb-0">
                    <thead class="table-light">
                        <tr>
                            <th>Timestamp</th>
                            <th>Device</th>
                            <th>Type</th>
                            <th>Detail</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($alerts as $alert): 
                            $sev = strtolower($alert['severity'] ?? 'info');
                            $badge = match($sev) {
                                'critical' => 'bg-danger',
                                'high' => 'bg-warning text-dark',
                                'medium' => 'bg-info text-dark',
                                default => 'bg-secondary'
                            };
                        ?>
                            <tr>
                                <td class="text-nowrap"><?= date('d M Y, H:i', strtotime($alert['run_timestamp'])) ?></td>
                                <td>
                                    <a href="device_detail.php?id=<?= urlencode($alert['device_id']) ?>" class="text-decoration-none fw-bold">
                                        <?= htmlspecialchars($alert['hostname']) ?>
                                    </a>
                                </td>
                                <td><span class="badge bg-secondary"><?= htmlspecialchars($alert['finding_type']) ?></span></td>
                                <td>
                                    <?= htmlspecialchars($alert['detail']) ?>
                                    <?php if ($alert['finding_type'] === 'Port' && $alert['is_expected'] == 0): ?>
                                        <span class="badge bg-danger ms-1">Unexpected</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="badge <?= $badge ?>"><?= ucfirst(htmlspecialchars($alert['severity'] ?? 'Info')) ?></span>
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
        $('#alertsTable').DataTable({
            "paging": true,
            "searching": true,
            "ordering": true,
            "info": true,
            "pageLength": 25,
            "order": [[ 0, "desc" ]], // Default sort by Timestamp descending
            "language": {
                "search": "Filter alerts:"
            }
        });
    });
</script>

<?php require_once 'includes/footer.php'; ?>