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
// FIXED: Changed c.check_run_id to cr.check_run_id in the second UNION block
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
    <!-- Page Header -->
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h2 class="mb-0">
                <i class="bi bi-shield-exclamation me-2"></i>Anomalies & Risks
                <i class="bi bi-question-circle text-muted ms-2" 
                   data-bs-toggle="tooltip" 
                   data-bs-title="Unified view of unusual patterns and high-risk configurations detected by agents"
                   style="cursor: help; font-size: 0.6em; vertical-align: middle;"></i>
            </h2>
            <p class="text-muted mb-0 mt-1">Identify potential security issues before they become breaches</p>
        </div>
        <span class="badge bg-info text-dark fs-6">Unified Threat View</span>
    </div>

    <!-- Info Banner - What is this page? -->
    <div class="alert alert-info d-flex align-items-start mb-4" role="alert">
        <i class="bi bi-info-circle-fill me-3 mt-1 fs-5"></i>
        <div>
            <h6 class="alert-heading mb-2">What are Anomalies & Risks?</h6>
            <p class="mb-2 small">
                This page combines lightweight log analysis and port scanning results to highlight unusual patterns 
                or misconfigurations that may indicate security issues. Unlike standard alerts, anomalies often point 
                to suspicious behavior (like repeated failed logins) or risky exposure (like open SMB ports).
            </p>
            <button class="btn btn-sm btn-link p-0 mt-2" type="button" data-bs-toggle="collapse" data-bs-target="#anomaliesHelp" aria-expanded="false"
                    data-bs-toggle="tooltip" data-bs-title="Expand to see usage instructions">
                Show how to use this page
            </button>
            <div class="collapse mt-2" id="anomaliesHelp">
                <div class="card card-body bg-light small">
                    <p class="mb-2"><strong>How to use this page:</strong></p>
                    <ul class="mb-2">
                        <li><strong>Chart:</strong> Shows the most common types of log anomalies detected across your network in the last 7 days.</li>
                        <li><strong>Table:</strong> Lists specific high-severity findings. Use the search box to filter by hostname, source (Log/Port), or type.</li>
                        <li><strong>Action:</strong> If you see a "Critical" or "High" finding, click into the device details to investigate the specific process or configuration causing it.</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <!-- Summary KPI Cards -->
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card bg-warning text-dark shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-black-50 text-uppercase small">
                        Log Anomalies (24h)
                        <i class="bi bi-question-circle ms-1" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Unusual patterns in system logs (e.g., failed logins, suspicious processes) detected in the last 24 hours."
                           style="cursor: help;"></i>
                    </h6>
                    <h2 class="fw-bold"><?= number_format($stats['log_anomalies'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-danger text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">
                        Dangerous Ports (24h)
                        <i class="bi bi-question-circle ms-1" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="High-risk network ports (e.g., RDP:3389, SMB:445) detected as open in the last 24 hours."
                           style="cursor: help;"></i>
                    </h6>
                    <h2 class="fw-bold"><?= number_format($stats['dangerous_ports'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-secondary text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">
                        Unhealthy Devices (24h)
                        <i class="bi bi-question-circle ms-1" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Devices not reporting a 'healthy' status in the last 24 hours due to findings or connectivity issues."
                           style="cursor: help;"></i>
                    </h6>
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
                    <h5 class="mb-0">
                        Top Anomaly Types (7 Days)
                        <i class="bi bi-question-circle text-muted ms-2" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="The most frequently occurring log anomaly categories across all devices over the past week."
                           style="cursor: help;"></i>
                    </h5>
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
                                        <th>
                                            Time
                                            <i class="bi bi-question-circle text-muted ms-1" 
                                               data-bs-toggle="tooltip" 
                                               data-bs-title="When the anomaly or port risk was detected."
                                               style="cursor: help;"></i>
                                        </th>
                                        <th>
                                            Hostname
                                            <i class="bi bi-question-circle text-muted ms-1" 
                                               data-bs-toggle="tooltip" 
                                               data-bs-title="The name of the endpoint where the issue was found."
                                               style="cursor: help;"></i>
                                        </th>
                                        <th>
                                            Source
                                            <i class="bi bi-question-circle text-muted ms-1" 
                                               data-bs-toggle="tooltip" 
                                               data-bs-title="Whether the finding came from 'Log' analysis or 'Port' scanning."
                                               style="cursor: help;"></i>
                                        </th>
                                        <th>
                                            Type
                                            <i class="bi bi-question-circle text-muted ms-1" 
                                               data-bs-toggle="tooltip" 
                                               data-bs-title="The specific anomaly type (e.g., failed_logins) or port/protocol combination."
                                               style="cursor: help;"></i>
                                        </th>
                                        <th>
                                            Details
                                            <i class="bi bi-question-circle text-muted ms-1" 
                                               data-bs-toggle="tooltip" 
                                               data-bs-title="Additional context, such as the process name associated with the port or specific log details."
                                               style="cursor: help;"></i>
                                        </th>
                                        <th>
                                            Severity
                                            <i class="bi bi-question-circle text-muted ms-1" 
                                               data-bs-toggle="tooltip" 
                                               data-bs-title="The risk level assigned to this finding."
                                               style="cursor: help;"></i>
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($findings as $f): 
                                        $badge_class = 'bg-info text-dark';
                                        $tooltip_text = 'Informational finding';
                                        if ($f['severity'] === 'critical') {
                                            $badge_class = 'bg-danger';
                                            $tooltip_text = 'Critical: Immediate investigation required.';
                                        } elseif ($f['severity'] === 'high') {
                                            $badge_class = 'bg-warning text-dark';
                                            $tooltip_text = 'High: Needs attention soon.';
                                        }
                                    ?>
                                    <tr>
                                        <td><small><?= date('d M H:i', strtotime($f['created_at'])) ?></small></td>
                                        <td>
                                            <strong><?= htmlspecialchars($f['hostname'] ?? 'Unknown') ?></strong><br>
                                            <small class="text-muted"><?= htmlspecialchars($f['os_family'] ?? '') ?></small>
                                        </td>
                                        <td>
                                            <span class="badge bg-secondary"
                                                  data-bs-toggle="tooltip" 
                                                  data-bs-title="Source: <?= htmlspecialchars($f['source']) ?>"
                                                  style="cursor: help;">
                                                <?= htmlspecialchars($f['source']) ?>
                                            </span>
                                        </td>
                                        <td><?= htmlspecialchars($f['type']) ?></td>
                                        <td><small class="text-muted"><?= htmlspecialchars($f['details'] ?? 'N/A') ?></small></td>
                                        <td>
                                            <span class="badge <?= $badge_class ?>" 
                                                  data-bs-toggle="tooltip" 
                                                  data-bs-title="<?= $tooltip_text ?>"
                                                  style="display: inline-block; padding: 0.4em 0.6em; font-size: 0.85em; border-radius: 0.25rem; cursor: help;">
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
    // Initialize Bootstrap Tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            trigger: 'hover',
            placement: 'auto'
        })
    })

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