<?php
/**
* NetSentinel Recent Alerts Page
* Displays unified security findings with solid color-coded
* severity badges for quick situational awareness.
*/
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}
$page_title = 'Recent Alerts';

// 1. Fetch Summary Counts for the top cards
$stats = $pdo->query("
    SELECT
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count
    FROM port_finding
")->fetch(PDO::FETCH_ASSOC);

// 2. Fetch the main alerts feed
// PERFORMANCE: UNION ALL merges Port and Firewall findings into a single chronological feed.
$stmt = $pdo->query("
    SELECT c.run_timestamp, d.hostname, d.device_id, 'Port' AS finding_type,
        CONCAT('Port ', p.port_number, ' (', COALESCE(p.process_name, 'Unknown'), ')') AS detail,
        p.severity, p.is_expected
    FROM port_finding p
    JOIN check_run c ON p.check_run_id = c.check_run_id
    JOIN device d ON c.device_id = d.device_id
    UNION ALL
    SELECT c.run_timestamp, d.hostname, d.device_id, 'Firewall' AS finding_type,
        CONCAT('Profile: ', COALESCE(f.profile, 'Unknown'), ' | Risky Rules: ', f.risky_rule_count) AS detail,
        CASE WHEN f.status = 'Warning' THEN 'high' ELSE 'info' END AS severity, NULL AS is_expected
    FROM firewall_finding f
    JOIN check_run c ON f.check_run_id = c.check_run_id
    JOIN device d ON c.device_id = d.device_id
    ORDER BY run_timestamp DESC LIMIT 500
");
$alerts = $stmt->fetchAll(PDO::FETCH_ASSOC);

include __DIR__ . '/includes/header.php';
?>
<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2> Recent Security Alerts</h2>
        <span class="badge bg-secondary"><?= count($alerts) ?> Total Alerts</span>
    </div>

    <!-- Summary Cards -->
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card bg-danger text-white shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Critical</h6>
                    <h2 class="fw-bold"><?= number_format($stats['critical_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-warning text-dark shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-black-50 text-uppercase small">High</h6>
                    <h2 class="fw-bold"><?= number_format($stats['high_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-dark text-white shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Medium</h6>
                    <h2 class="fw-bold"><?= number_format($stats['medium_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
    </div>

    <!-- Alerts Table -->
    <div class="card">
        <div class="card-header bg-white">
            <h5 class="mb-0">Unified Alert Feed</h5>
        </div>
        <div class="card-body">
            <?php if (empty($alerts)): ?>
                <div class="text-center py-5">
                    <i class="bi bi-bell-slash display-4 text-muted"></i>
                    <p class="text-muted mt-3">No recent alerts found. All systems appear to be secure.</p>
                </div>
            <?php else: ?>
                <div class="table-responsive">
                    <table class="table table-hover table-striped" id="alertsTable" style="width:100%">
                        <thead class="table-dark">
                            <tr>
                                <th>Timestamp</th>
                                <th>Hostname</th>
                                <th>Type</th>
                                <th>Detail</th>
                                <th>Severity</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($alerts as $alert): 
                                // Determine badge color based on severity
                                $badge_class = 'bg-secondary';
                                if ($alert['severity'] === 'critical') $badge_class = 'bg-danger';
                                elseif ($alert['severity'] === 'high') $badge_class = 'bg-warning text-dark';
                                elseif ($alert['severity'] === 'medium') $badge_class = 'bg-dark';
                            ?>
                            <tr>
                                <td><small><?= date('d M Y, H:i', strtotime($alert['run_timestamp'])) ?></small></td>
                                <td><strong><?= htmlspecialchars($alert['hostname'] ?? 'Unknown') ?></strong></td>
                                <td><span class="badge bg-info text-dark"><?= htmlspecialchars($alert['finding_type']) ?></span></td>
                                <td><?= htmlspecialchars($alert['detail']) ?></td>
                                <td>
                                    <span class="badge <?= $badge_class ?>" style="display: inline-block; padding: 0.4em 0.6em; font-size: 0.85em; border-radius: 0.25rem;">
                                        <?= strtoupper(htmlspecialchars($alert['severity'])) ?>
                                    </span>
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

<script>
$(document).ready(function() {
    $('#alertsTable').DataTable({
        order: [[0, 'desc']],
        pageLength: 25,
        language: {
            search: "Search alerts:"
        }
    });
});
</script>
<?php include __DIR__ . '/includes/footer.php'; ?>