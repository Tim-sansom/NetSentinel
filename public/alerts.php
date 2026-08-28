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
    <!-- Page Header -->
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h2 class="mb-0">
                <i class="bi bi-bell me-2"></i>Recent Security Alerts
                <i class="bi bi-question-circle text-muted ms-2" 
                   data-bs-toggle="tooltip" 
                   data-bs-title="Security findings detected by NetSentinel agents across your network"
                   style="cursor: help; font-size: 0.6em; vertical-align: middle;"></i>
            </h2>
            <p class="text-muted mb-0 mt-1">Review and prioritize potential security risks on your endpoints</p>
        </div>
        <span class="badge bg-secondary fs-6"><?= count($alerts) ?> Total Alerts</span>
    </div>

    <!-- Info Banner - What is this page? -->
    <div class="alert alert-info d-flex align-items-start mb-4" role="alert">
        <i class="bi bi-info-circle-fill me-3 mt-1 fs-5"></i>
        <div>
            <h6 class="alert-heading mb-2">What are Security Alerts?</h6>
            <p class="mb-2 small">
                Alerts are generated when NetSentinel agents detect potential security misconfigurations, open risky ports, 
                or firewall issues on your endpoints. Higher severity indicates a greater need for immediate investigation.
            </p>
            <button class="btn btn-sm btn-link p-0 mt-2" type="button" data-bs-toggle="collapse" data-bs-target="#alertsHelp" aria-expanded="false"
                    data-bs-toggle="tooltip" data-bs-title="Expand to see severity definitions and usage tips">
                Show severity guide & tips
            </button>
            <div class="collapse mt-2" id="alertsHelp">
                <div class="card card-body bg-light small">
                    <p class="mb-2"><strong>Severity Levels:</strong></p>
                    <ul class="mb-2">
                        <li><span class="badge bg-danger me-2">CRITICAL</span> Immediate action required. (e.g., RDP/SSH exposed to the internet, critical vulnerabilities).</li>
                        <li><span class="badge bg-warning text-dark me-2">HIGH</span> Needs attention soon. (e.g., non-standard open ports, firewall warnings).</li>
                        <li><span class="badge bg-dark text-white me-2">MEDIUM</span> Routine findings or informational checks. (e.g., standard port states, expected configurations).</li>
                    </ul>
                    <p class="mb-0"><strong>How to use this page:</strong> Use the search box to filter alerts by hostname or detail. Click the "Timestamp" or "Severity" column headers to sort and prioritize the most urgent issues first.</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Summary Cards -->
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card bg-danger text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">
                        Critical
                        <i class="bi bi-question-circle ms-1" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Immediate action required. Examples: Exposed RDP/SSH, critical vulnerabilities."
                           style="cursor: help;"></i>
                    </h6>
                    <h2 class="fw-bold"><?= number_format($stats['critical_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-warning text-dark shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-black-50 text-uppercase small">
                        High
                        <i class="bi bi-question-circle ms-1" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Needs attention soon. Examples: Non-standard open ports, firewall warnings."
                           style="cursor: help;"></i>
                    </h6>
                    <h2 class="fw-bold"><?= number_format($stats['high_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-dark text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">
                        Medium
                        <i class="bi bi-question-circle ms-1" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Routine findings or informational checks. Examples: Standard port states."
                           style="cursor: help;"></i>
                    </h6>
                    <h2 class="fw-bold"><?= number_format($stats['medium_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
    </div>

    <!-- Alerts Table -->
    <div class="card shadow-sm">
        <div class="card-header bg-white py-3">
            <h5 class="mb-0 text-muted">
                Unified Alert Feed
                <i class="bi bi-question-circle text-muted ms-2" 
                   data-bs-toggle="tooltip" 
                   data-bs-title="A combined chronological list of all port and firewall findings across all devices."
                   style="cursor: help;"></i>
            </h5>
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
                                <th>
                                    Timestamp
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The exact date and time the agent detected this finding."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    Hostname
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The name of the endpoint device where the issue was detected."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    Type
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The source of the alert: 'Port' (network port scan) or 'Firewall' (host firewall status)."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    Detail
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="Specifics of the finding, such as the port number, protocol, or associated process."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    Severity
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The risk level assigned to this specific finding."
                                       style="cursor: help;"></i>
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($alerts as $alert): 
                                // Determine badge color based on severity
                                $badge_class = 'bg-secondary';
                                $tooltip_text = 'Informational finding';
                                if ($alert['severity'] === 'critical') {
                                    $badge_class = 'bg-danger';
                                    $tooltip_text = 'Critical: Immediate action required.';
                                } elseif ($alert['severity'] === 'high') {
                                    $badge_class = 'bg-warning text-dark';
                                    $tooltip_text = 'High: Needs attention soon.';
                                } elseif ($alert['severity'] === 'medium') {
                                    $badge_class = 'bg-dark';
                                    $tooltip_text = 'Medium: Routine or informational finding.';
                                }
                            ?>
                            <tr>
                                <td><small><?= date('d M Y, H:i', strtotime($alert['run_timestamp'])) ?></small></td>
                                <td><strong><?= htmlspecialchars($alert['hostname'] ?? 'Unknown') ?></strong></td>
                                <td>
                                    <span class="badge bg-info text-dark"
                                          data-bs-toggle="tooltip" 
                                          data-bs-title="Source: <?= htmlspecialchars($alert['finding_type']) ?> check"
                                          style="cursor: help;">
                                        <?= htmlspecialchars($alert['finding_type']) ?>
                                    </span>
                                </td>
                                <td><?= htmlspecialchars($alert['detail']) ?></td>
                                <td>
                                    <span class="badge <?= $badge_class ?>" 
                                          data-bs-toggle="tooltip" 
                                          data-bs-title="<?= $tooltip_text ?>"
                                          style="display: inline-block; padding: 0.4em 0.6em; font-size: 0.85em; border-radius: 0.25rem; cursor: help;">
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
    // Initialize Bootstrap Tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            trigger: 'hover',
            placement: 'auto'
        })
    })

    $('#alertsTable').DataTable({
        order: [[0, 'desc']], // Sort by Timestamp descending by default
        pageLength: 25,
        language: {
            search: "Search alerts:"
        }
    });
});
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>