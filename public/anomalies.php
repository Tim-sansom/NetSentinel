<?php
/**
 * NetSentinel - Anomalies & Risks Dashboard Page
 * ================================================================================
 * 
 * PURPOSE:
 * Provides a unified, chronological view of security anomalies (log events) and 
 * risks (dangerous open ports) detected across the monitored endpoint fleet.
 * 
 * ACADEMIC SIGNIFICANCE:
 * This module demonstrates advanced SQL aggregation and Multi-Tenant Isolation (SR2).
 * By using a `UNION ALL` query, it merges disparate finding types (log vs. port) 
 * into a single, cohesive threat feed, simulating a lightweight SIEM correlation engine 
 * without the performance overhead of a full enterprise SIEM.
 * 
 * SECURITY BOUNDARIES:
 * - SR2 (Access Control): Strict Row-Level Security (RLS) enforced on all aggregate 
 *   and detailed queries via `device_group_id` joins.
 * - SR3 (Output Sanitisation): All dynamic data is escaped via htmlspecialchars() 
 *   to prevent Cross-Site Scripting (XSS) in the findings table.
 * 
 * @author Tim Sansom
 * @version 1.0
 * @date 2026
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';

// Enforce authentication before any data access
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$page_title = 'Anomalies & Risks';

// ===========================================================================
// ROLE AND SCOPE DETERMINATION (SR2)
// ===========================================================================
// Normalize role to lowercase to prevent case-sensitivity bypasses
$current_role = strtolower($_SESSION['role'] ?? '');
$is_super_admin = ($current_role === 'super_admin');
$is_admin = ($current_role === 'admin' || $is_super_admin);
$user_group_id = $_SESSION['group_id'] ?? null;

// ===========================================================================
// 1. FETCH 24-HOUR SUMMARY STATISTICS (KPI CARDS)
// ===========================================================================
// Uses correlated subqueries to calculate rolling 24-hour metrics efficiently.
if ($is_super_admin) {
    // Super Admins: Global visibility across all tenants
    $stats = $pdo->query("
        SELECT 
            (SELECT COUNT(*) FROM log_finding lf JOIN check_run cr ON lf.check_run_id = cr.check_run_id WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as log_anomalies,
            (SELECT COUNT(*) FROM port_finding pf JOIN check_run cr ON pf.check_run_id = cr.check_run_id WHERE pf.severity IN ('high', 'critical') AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as dangerous_ports,
            (SELECT COUNT(DISTINCT d.device_id) FROM device d JOIN check_run cr ON d.device_id = cr.device_id WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) AND d.current_health_status != 'healthy') as unhealthy_devices
    ")->fetch(PDO::FETCH_ASSOC);
} else {
    if ($user_group_id) {
        // Standard Admins: STRICT RLS. 
        // Every subquery explicitly JOINs the `device` table to filter by `device_group_id`.
        $stmt = $pdo->prepare("
            SELECT 
                (SELECT COUNT(*) FROM log_finding lf JOIN check_run cr ON lf.check_run_id = cr.check_run_id JOIN device d ON cr.device_id = d.device_id WHERE d.device_group_id = ? AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as log_anomalies,
                (SELECT COUNT(*) FROM port_finding pf JOIN check_run cr ON pf.check_run_id = cr.check_run_id JOIN device d ON cr.device_id = d.device_id WHERE d.device_group_id = ? AND pf.severity IN ('high', 'critical') AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as dangerous_ports,
                (SELECT COUNT(DISTINCT d.device_id) FROM device d JOIN check_run cr ON d.device_id = cr.device_id WHERE d.device_group_id = ? AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) AND d.current_health_status != 'healthy') as unhealthy_devices
        ");
        $stmt->execute([$user_group_id, $user_group_id, $user_group_id]);
        $stats = $stmt->fetch(PDO::FETCH_ASSOC);
    } else {
        // Defensive fallback for users without an assigned group
        $stats = ['log_anomalies' => 0, 'dangerous_ports' => 0, 'unhealthy_devices' => 0];
    }
}

// ===========================================================================
// 2. FETCH CHART DATA (7-DAY AGGREGATION)
// ===========================================================================
// Server-side aggregation (GROUP BY) ensures the frontend only receives 
// a lightweight JSON payload, satisfying NFR1 (Performance).
if ($is_super_admin) {
    $chart_data = $pdo->query("
        SELECT lf.anomaly_type, COUNT(*) as count 
        FROM log_finding lf 
        JOIN check_run cr ON lf.check_run_id = cr.check_run_id 
        WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY) 
        GROUP BY lf.anomaly_type ORDER BY count DESC LIMIT 5
    ")->fetchAll(PDO::FETCH_ASSOC);
} else {
    if ($user_group_id) {
        $stmt = $pdo->prepare("
            SELECT lf.anomaly_type, COUNT(*) as count 
            FROM log_finding lf 
            JOIN check_run cr ON lf.check_run_id = cr.check_run_id 
            JOIN device d ON cr.device_id = d.device_id
            WHERE d.device_group_id = ? AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY) 
            GROUP BY lf.anomaly_type ORDER BY count DESC LIMIT 5
        ");
        $stmt->execute([$user_group_id]);
        $chart_data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $chart_data = [];
    }
}

// Encode for Chart.js consumption
$chart_labels = json_encode(array_column($chart_data, 'anomaly_type'));
$chart_counts = json_encode(array_column($chart_data, 'count'));

// ===========================================================================
// 3. FETCH DETAILED FINDINGS (UNIFIED THREAT FEED)
// ===========================================================================
// Uses UNION ALL to merge log and port findings into a single chronological feed.
// UNION ALL is preferred over UNION here for performance, as we do not need 
// the overhead of duplicate row elimination.
if ($is_super_admin) {
    $findings = $pdo->query("
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
    ")->fetchAll(PDO::FETCH_ASSOC);
} else {
    if ($user_group_id) {
        // Standard Admins: RLS applied to both sides of the UNION ALL via a wrapper subquery
        $stmt = $pdo->prepare("
            SELECT source, type, count, severity, details, created_at, hostname, os_family FROM (
                SELECT 'Log' as source, lf.anomaly_type as type, lf.event_count as count, lf.severity, lf.details, cr.run_timestamp as created_at, d.hostname, d.os_family
                FROM log_finding lf
                JOIN check_run cr ON lf.check_run_id = cr.check_run_id
                JOIN device d ON cr.device_id = d.device_id
                WHERE d.device_group_id = ?
                UNION ALL
                SELECT 'Port' as source, CONCAT('Port ', pf.port_number, ' (', pf.protocol, ')') as type, 1 as count, pf.severity, pf.process_name as details, cr.run_timestamp as created_at, d.hostname, d.os_family
                FROM port_finding pf
                JOIN check_run cr ON pf.check_run_id = cr.check_run_id
                JOIN device d ON cr.device_id = d.device_id
                WHERE d.device_group_id = ? AND pf.severity IN ('high', 'critical')
            ) as combined
            ORDER BY created_at DESC LIMIT 200
        ");
        $stmt->execute([$user_group_id, $user_group_id]);
        $findings = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $findings = [];
    }
}

include __DIR__ . '/includes/header.php';
?>

<!-- ========================================================================= -->
<!-- HTML CONTENT - ANOMALIES DASHBOARD INTERFACE -->
<!-- ========================================================================= -->

<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h2 class="mb-0"><i class="bi bi-shield-exclamation me-2"></i>Anomalies & Risks</h2>
            <p class="text-muted mb-0 mt-1">Identify potential security issues before they become breaches</p>
        </div>
        <span class="badge bg-info text-dark fs-6">Unified Threat View</span>
    </div>

    <div class="alert alert-info d-flex align-items-start mb-4" role="alert">
        <i class="bi bi-info-circle-fill me-3 mt-1 fs-5"></i>
        <div>
            <h6 class="alert-heading mb-2">What are Anomalies & Risks?</h6>
            <p class="mb-2 small">This page combines lightweight log analysis and port scanning results to highlight unusual patterns or misconfigurations across your tenant's devices.</p>
        </div>
    </div>

    <!-- KPI Summary Cards -->
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card bg-warning text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Log Anomalies (24h)</h6>
                    <h2 class="fw-bold"><?= number_format($stats['log_anomalies'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-danger text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Dangerous Ports (24h)</h6>
                    <h2 class="fw-bold"><?= number_format($stats['dangerous_ports'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-secondary text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Unhealthy Devices (24h)</h6>
                    <h2 class="fw-bold"><?= number_format($stats['unhealthy_devices'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
    </div>

    <div class="row">
        <!-- Chart.js Visualization -->
        <div class="col-md-4 mb-4">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white"><h5 class="mb-0">Top Anomaly Types (7 Days)</h5></div>
                <div class="card-body d-flex align-items-center justify-content-center">
                    <?php if (empty($chart_data)): ?>
                        <p class="text-muted text-center">No anomaly data available for the last 7 days.</p>
                    <?php else: ?>
                        <canvas id="anomalyChart"></canvas>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Detailed Findings DataTable -->
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
                            <h5 class="mt-3">No High-Severity Findings</h5>
                            <p class="text-muted"><?php if ($is_admin): ?>No high-severity anomalies detected recently.<?php else: ?>You do not have access to any device anomaly data.<?php endif; ?></p>
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
                                        // Dynamic severity badge mapping for visual consistency
                                        $badge_class = $f['severity'] === 'critical' ? 'bg-danger' : ($f['severity'] === 'high' ? 'bg-warning text-dark' : 'bg-info text-dark');
                                    ?>
                                    <tr>
                                        <!-- SR3: Escape all dynamic output to prevent XSS -->
                                        <td><small><?= date('d M H:i', strtotime($f['created_at'])) ?></small></td>
                                        <td><strong><?= htmlspecialchars($f['hostname'] ?? 'Unknown') ?></strong></td>
                                        <td><span class="badge bg-secondary"><?= htmlspecialchars($f['source']) ?></span></td>
                                        <td><?= htmlspecialchars($f['type']) ?></td>
                                        <td><small class="text-muted"><?= htmlspecialchars($f['details'] ?? 'N/A') ?></small></td>
                                        <td><span class="badge <?= $badge_class ?>"><?= strtoupper(htmlspecialchars($f['severity'])) ?></span></td>
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

<!-- ========================================================================= -->
<!-- JAVASCRIPT - CHART.JS AND DATATABLES INITIALIZATION -->
<!-- ========================================================================= -->
<script>
$(document).ready(function() {
    // Initialize Bootstrap Tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) { 
        return new bootstrap.Tooltip(tooltipTriggerEl, { trigger: 'hover', placement: 'auto' }); 
    });

    // Initialize Doughnut Chart (Only if data exists)
    <?php if (!empty($chart_data)): ?>
    const ctx = document.getElementById('anomalyChart').getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: <?= $chart_labels ?>,
            datasets: [{
                data: <?= $chart_counts ?>,
                backgroundColor: ['#dc3545', '#ffc107', '#17a2b8', '#6c757d', '#0d6efd'],
                borderWidth: 0 // Clean, modern aesthetic without border lines
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { 
                legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } } 
            }
        }
    });
    <?php endif; ?>

    // Initialize DataTables for the unified findings feed
    $('#anomaliesTable').DataTable({
        order: [[0, 'desc']], // Default sort by Time (newest first)
        pageLength: 10,
        language: { search: "Filter findings:" }
    });
});
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>