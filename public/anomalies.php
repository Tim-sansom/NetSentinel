<?php
/**
 * NetSentinel Anomalies Page
 * Visualizes log anomalies, dangerous ports, and persistence 
 * mechanisms for proactive threat detection.
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

$page_title = 'Anomalies & Risks';

// 1. Fetch 24-Hour Summary Statistics (Combined Logs and Ports)
$stats = $pdo->query("
    SELECT 
    (SELECT COUNT(*) FROM log_finding lf JOIN check_run cr ON lf.check_run_id = cr.check_run_id WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as log_anomalies,
    (SELECT COUNT(*) FROM port_finding pf JOIN check_run cr ON pf.check_run_id = cr.check_run_id WHERE pf.severity IN ('high', 'critical') AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as dangerous_ports,
    (SELECT COUNT(DISTINCT d.device_id) FROM device d JOIN check_run cr ON d.device_id = cr.device_id WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) AND d.current_health_status != 'healthy') as unhealthy_devices
")->fetch(PDO::FETCH_ASSOC);

// 2. Fetch Chart Data (Top Anomaly Types in last 7 days from logs)
$chart_data = $pdo->query("
    SELECT lf.anomaly_type, COUNT(*) as count 
    FROM log_finding lf 
    JOIN check_run cr ON lf.check_run_id = cr.check_run_id 
    WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY) 
    GROUP BY lf.anomaly_type ORDER BY count DESC LIMIT 5
")->fetchAll(PDO::FETCH_ASSOC);

$chart_labels = json_encode(array_column($chart_data, 'anomaly_type'));
$chart_counts = json_encode(array_column($chart_data, 'count'));

// 3. Fetch Detailed Findings for DataTable (Unified View)
$stmt = $pdo->query("
    SELECT 'Log' as source, lf.anomaly_type as type, lf.event_count as count, lf.severity, lf.details, cr.run_timestamp as created_at, d.hostname, d.os_family
    FROM log_finding lf
    JOIN check_run cr ON lf.check_run_id = cr.check_run_id
    JOIN device d ON cr.device_id = d.device_id
    UNION ALL
    SELECT 'Port' as source, CONCAT('Port ', pf.port_number, ' (', pf.protocol, ')') as type, 1 as count, pf.severity, pf.process_name as details, cr.run_timestamp as created_at, d.hostname, d.os_family
    FROM port_finding pf
    JOIN check_run cr ON pf.check_run_id = cr.check_run_id
    JOIN device d ON cr.device_id = d.device_id
    WHERE pf.severity IN ('high', 'critical')
    ORDER BY created_at DESC LIMIT 200
");
$findings = $stmt->fetchAll(PDO::FETCH_ASSOC);

include __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>⚠️ Anomalies & Risks</h2>
        <span class="badge bg-info text-dark">Unified Threat View</span>
    </div>

    <!-- Summary KPI Cards -->
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card bg-warning text-dark shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-black-50 text-uppercase small">Log Anomalies (24h)</h6>
                    <h2 class="fw-bold"><?= number_format($stats['log_anomalies'] ?? 0) ?></h6>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-danger text-white shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Dangerous Ports (24h)</h6>
                    <h2 class="fw-bold"><?= number_format($stats['dangerous_ports'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-secondary text-white shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Unhealthy Devices (24h)</h6>
                    <h2 class="fw-bold"><?= number_format($stats['unhealthy_devices'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
    </div>

    <div class="row">
        <!-- Chart Section -->
        <div class="col-md-4 mb-4">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white">
                    <h5 class="mb-0">Top Anomaly Types (7 Days)</h5>
                </div>
                <div class="card-body d-flex align-items-center justify-content-center">
                    <?php if (empty($chart_data)): ?>
                        <p class="text-muted text-center">No anomaly data available for the last 7 days.</p>
                    <?php else: ?>
                        <canvas id="anomalyChart"></canvas>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- DataTable Section -->
        <div class="col-md-8 mb-4">
            <div class="card shadow-sm">
                <div class="card-header bg-white d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">Recent Findings</h5>
                    <small class="text-muted">Showing up to 200 recent high-severity events</small>
                </div>
                <div class="card-body">
                    <?php if (empty($findings)): ?>
                        <div class="text-center py-5">
                            <i class="bi bi-shield-check display-4 text-success"></i>
                            <p class="text-muted mt-3">No high-severity anomalies or dangerous ports detected recently.</p>
                        </div>
                    <?php else: ?>
                        <div class="table-responsive">
                            <table class="table table-hover table-striped" id="anomaliesTable" style="width:100%">
                                <thead class="table-dark">
                                    <tr>
                                        <th>Time</th>
                                        <th>Hostname</th>
                                        <th>Source</th>
                                        <th>Type</th>
                                        <th>Details</th>
                                        <th>Severity</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($findings as $f): 
                                        $badge_class = 'bg-info text-dark';
                                        if ($f['severity'] === 'critical') $badge_class = 'bg-danger';
                                        elseif ($f['severity'] === 'high') $badge_class = 'bg-warning text-dark';
                                    ?>
                                    <tr>
                                        <td><small><?= date('d M H:i', strtotime($f['created_at'])) ?></small></td>
                                        <td>
                                            <strong><?= htmlspecialchars($f['hostname'] ?? 'Unknown') ?></strong><br>
                                            <small class="text-muted"><?= htmlspecialchars($f['os_family'] ?? '') ?></small>
                                        </td>
                                        <td><span class="badge bg-secondary"><?= htmlspecialchars($f['source']) ?></span></td>
                                        <td><?= htmlspecialchars($f['type']) ?></td>
                                        <td><small class="text-muted"><?= htmlspecialchars($f['details'] ?? 'N/A') ?></small></td>
                                        <td>
                                            <span class="badge <?= $badge_class ?>" style="display: inline-block; padding: 0.4em 0.6em; font-size: 0.85em; border-radius: 0.25rem;">
                                                <?= strtoupper(htmlspecialchars($f['severity'])) ?>
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
    </div>
</div>

<script>
$(document).ready(function() {
    // Initialize Chart.js
    <?php if (!empty($chart_data)): ?>
    const ctx = document.getElementById('anomalyChart').getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: <?= $chart_labels ?>,
            datasets: [{
                data: <?= $chart_counts ?>,
                backgroundColor: ['#dc3545', '#ffc107', '#17a2b8', '#6c757d', '#0d6efd'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { boxWidth: 12, font: { size: 11 } }
                }
            }
        }
    });
    <?php endif; ?>

    // Initialize DataTables
    $('#anomaliesTable').DataTable({
        order: [[0, 'desc']],
        pageLength: 10,
        language: {
            search: "Filter findings:"
        },
        columnDefs: [
            { targets: [4], width: '25%' } // Give details column more space
        ]
    });
});
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>