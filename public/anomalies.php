<?php
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
// FIXED: Changed lf.created_at to cr.run_timestamp
$stats = $pdo->query("
    SELECT 
        (SELECT COUNT(*) FROM log_finding lf JOIN check_run cr ON lf.check_run_id = cr.check_run_id WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as log_anomalies,
        (SELECT COUNT(*) FROM port_finding pf JOIN check_run cr ON pf.check_run_id = cr.check_run_id WHERE pf.severity IN ('high', 'critical') AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as dangerous_ports,
        (SELECT COUNT(DISTINCT d.device_id) FROM device d JOIN check_run cr ON d.device_id = cr.device_id WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) AND d.current_health_status != 'healthy') as unhealthy_devices
")->fetch(PDO::FETCH_ASSOC);

// 2. Fetch Chart Data (Top Anomaly Types in last 7 days from logs)
// FIXED: Changed lf.created_at to cr.run_timestamp
$chart_data = $pdo->query("
    SELECT lf.anomaly_type, COUNT(*) as count
    FROM log_finding lf
    JOIN check_run cr ON lf.check_run_id = cr.check_run_id
    WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    GROUP BY lf.anomaly_type
    ORDER BY count DESC
    LIMIT 5
")->fetchAll(PDO::FETCH_ASSOC);

$chart_labels = json_encode(array_column($chart_data, 'anomaly_type'));
$chart_counts = json_encode(array_column($chart_data, 'count'));

// 3. Fetch Detailed Findings for DataTable (Unified View)
// FIXED: Changed lf.created_at to cr.run_timestamp as 'created_at'
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
    
    ORDER BY created_at DESC
    LIMIT 200
");
$findings = $stmt->fetchAll(PDO::FETCH_ASSOC);

include __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2>⚠️ Anomalies & Risks</h2>
        <span class="badge bg-info text-dark">
            <i class="bi bi-shield-check"></i> Unified Situational Awareness
        </span>
    </div>

    <!-- 1. VISUAL LAYER: Situational Awareness KPIs -->
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card bg-danger text-white shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Log Anomalies (24h)</h6>
                    <h2 class="fw-bold"><?= number_format($stats['log_anomalies'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-warning text-dark shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-black-50 text-uppercase small">Dangerous Ports Open</h6>
                    <h2 class="fw-bold"><?= number_format($stats['dangerous_ports'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-dark text-white shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Unhealthy Endpoints (24h)</h6>
                    <h2 class="fw-bold"><?= number_format($stats['unhealthy_devices'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
    </div>

    <div class="row mb-4">
        <!-- Chart.js Visualisation -->
        <div class="col-md-5">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white">
                    <h6 class="mb-0">Top Log Anomaly Types (Last 7 Days)</h6>
                </div>
                <div class="card-body d-flex align-items-center justify-content-center">
                    <canvas id="anomalyChart" style="max-height: 250px;"></canvas>
                </div>
            </div>
        </div>

        <!-- Context / Guidance Panel -->
        <div class="col-md-7">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white">
                    <h6 class="mb-0">Investigation Guidance</h6>
                </div>
                <div class="card-body">
                    <p class="text-muted small mb-2">
                        This unified view aggregates <strong>summary metadata</strong> from endpoint logs and port scans. 
                        No raw logs are transmitted, satisfying NFR1 (low resource overhead).
                    </p>
                    <ul class="small text-muted mb-0">
                        <li><strong>brute_force / failed_logon:</strong> Indicates potential credential stuffing. Check the "Event Count" for severity.</li>
                        <li><strong>suspicious_cron / startup:</strong> Indicates potential malware persistence mechanisms.</li>
                        <li><strong>Dangerous Ports:</strong> Ports like 4444, 23, or 3389 open on endpoints that shouldn't have them.</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <!-- 2. INVESTIGATIVE LAYER: Drill-down DataTable -->
    <div class="card shadow-sm">
        <div class="card-header bg-white d-flex justify-content-between align-items-center">
            <h6 class="mb-0">Recent High-Risk Findings</h6>
            <small class="text-muted">Click column headers to sort</small>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover table-striped" id="anomalyTable" style="width:100%">
                    <thead class="table-dark">
                        <tr>
                            <th>Timestamp</th>
                            <th>Source</th>
                            <th>Hostname</th>
                            <th>OS</th>
                            <th>Anomaly Type</th>
                            <th>Count</th>
                            <th>Severity</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($findings as $f): ?>
                            <tr>
                                <td><?= htmlspecialchars(date('Y-m-d H:i', strtotime($f['created_at']))) ?></td>
                                <td><span class="badge bg-<?= $f['source'] === 'Log' ? 'info' : 'secondary' ?>"><?= $f['source'] ?></span></td>
                                <td class="fw-bold"><?= htmlspecialchars($f['hostname'] ?? 'Unknown') ?></td>
                                <td><small><?= htmlspecialchars($f['os_family'] ?? 'Unknown') ?></small></td>
                                <td><?= htmlspecialchars(str_replace('_', ' ', ucwords($f['type'], '_'))) ?></td>
                                <td><span class="badge bg-secondary"><?= number_format($f['count']) ?></span></td>
                                <td>
                                    <?php 
                                    $sev = strtolower($f['severity']);
                                    $badge = $sev === 'critical' ? 'danger' : ($sev === 'high' ? 'warning' : 'info');
                                    ?>
                                    <span class="badge bg-<?= $badge ?> text-<?= $badge === 'warning' ? 'dark' : 'white' ?>">
                                        <?= ucfirst($sev) ?>
                                    </span>
                                </td>
                                <td>
                                    <small class="text-muted">
                                        <?= htmlspecialchars(substr($f['details'] ?? 'No details', 0, 60)) ?><?= strlen($f['details'] ?? '') > 60 ? '...' : '' ?>
                                    </small>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    // 1. Initialize DataTables for investigative drill-down
    $('#anomalyTable').DataTable({
        order: [[0, 'desc']], // Sort by Timestamp descending (newest first)
        pageLength: 15,
        language: {
            search: "Filter by hostname, anomaly type, or severity:"
        },
        columnDefs: [
            { targets: [7], orderable: false } // Disable sorting on truncated details
        ]
    });

    // 2. Initialize Chart.js for situational awareness
    const ctx = document.getElementById('anomalyChart').getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: <?= $chart_labels ?: '["No Data"]' ?>,
            datasets: [{
                data: <?= $chart_counts ?: '[1]' ?>,
                backgroundColor: ['#dc3545', '#ffc107', '#0dcaf0', '#6c757d', '#198754'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom' } }
        }
    });
});
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>