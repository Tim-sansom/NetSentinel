<?php
/**
 * NetSentinel - Recent Security Alerts Page
 * ================================================================================
 * 
 * PURPOSE:
 * Provides a unified, chronological view of security alerts (open ports, firewall 
 * misconfigurations) detected across the monitored endpoint fleet.
 * 
 * ACADEMIC SIGNIFICANCE:
 * This module demonstrates advanced SQL aggregation and Multi-Tenant Isolation (SR2).
 * By using a `UNION ALL` query, it merges disparate finding types (port vs. firewall) 
 * into a single, cohesive threat feed, simulating a lightweight SIEM correlation engine 
 * without the performance overhead of a full enterprise SIEM.
 * 
 * SECURITY BOUNDARIES:
 * - SR2 (Access Control): Strict Row-Level Security (RLS) enforced on all aggregate 
 *   and detailed queries via `device_group_id` joins.
 * - SR3 (Output Sanitisation): All dynamic data is escaped via htmlspecialchars() 
 *   to prevent Cross-Site Scripting (XSS) in the alerts table.
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

$page_title = 'Recent Alerts';

// ===========================================================================
// ROLE AND SCOPE DETERMINATION (SR2)
// ===========================================================================
// Normalize role to lowercase to prevent case-sensitivity bypasses
$current_role = strtolower($_SESSION['role'] ?? '');
$is_super_admin = ($current_role === 'super_admin');
$is_admin = ($current_role === 'admin' || $is_super_admin);
$user_group_id = $_SESSION['group_id'] ?? null;

// ===========================================================================
// 1. FETCH SUMMARY COUNTS (KPI CARDS)
// ===========================================================================
// Uses conditional aggregation (SUM/CASE) for efficient single-pass counting.
if ($is_super_admin) {
    // Super Admins: Global visibility across all tenants
    $stats = $pdo->query("
        SELECT 
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count, 
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count, 
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count 
        FROM port_finding
    ")->fetch(PDO::FETCH_ASSOC);
} else {
    if ($user_group_id) {
        // Standard Admins: STRICT RLS. 
        // Joins the `device` table to filter findings by the user's `device_group_id`.
        $stmt = $pdo->prepare("
            SELECT 
                SUM(CASE WHEN pf.severity = 'critical' THEN 1 ELSE 0 END) as critical_count, 
                SUM(CASE WHEN pf.severity = 'high' THEN 1 ELSE 0 END) as high_count, 
                SUM(CASE WHEN pf.severity = 'medium' THEN 1 ELSE 0 END) as medium_count 
            FROM port_finding pf 
            JOIN check_run cr ON pf.check_run_id = cr.check_run_id 
            JOIN device d ON cr.device_id = d.device_id 
            WHERE d.device_group_id = ?
        ");
        $stmt->execute([$user_group_id]);
        $stats = $stmt->fetch(PDO::FETCH_ASSOC);
    } else {
        // Defensive fallback for users without an assigned group
        $stats = ['critical_count' => 0, 'high_count' => 0, 'medium_count' => 0];
    }
}

// ===========================================================================
// 2. FETCH UNIFIED ALERT FEED
// ===========================================================================
// Uses UNION ALL to merge port and firewall findings into a single chronological feed.
// UNION ALL is preferred over UNION here for performance, as it skips the overhead 
// of duplicate row elimination, which is unnecessary for distinct finding types.
if ($is_super_admin) {
    $alerts_query = "
        SELECT c.run_timestamp, d.hostname, d.device_id, 'Port' AS finding_type, 
               CONCAT('Port ', p.port_number, ' (', COALESCE(p.process_name, 'Unknown'), ')') AS detail, p.severity 
        FROM port_finding p 
        JOIN check_run c ON p.check_run_id = c.check_run_id 
        JOIN device d ON c.device_id = d.device_id 
        UNION ALL 
        SELECT c.run_timestamp, d.hostname, d.device_id, 'Firewall' AS finding_type, 
               CONCAT('Profile: ', COALESCE(f.profile, 'Unknown'), ' | Risky Rules: ', f.risky_rule_count) AS detail, 
               CASE WHEN f.status = 'Warning' THEN 'high' ELSE 'info' END AS severity 
        FROM firewall_finding f 
        JOIN check_run c ON f.check_run_id = c.check_run_id 
        JOIN device d ON c.device_id = d.device_id 
        ORDER BY run_timestamp DESC 
        LIMIT 500
    ";
    $alerts = $pdo->query($alerts_query)->fetchAll(PDO::FETCH_ASSOC);
} else {
    if ($user_group_id) {
        // Standard Admins: RLS applied to both sides of the UNION ALL
        $alerts_query = "
            SELECT c.run_timestamp, d.hostname, d.device_id, 'Port' AS finding_type, 
                   CONCAT('Port ', p.port_number, ' (', COALESCE(p.process_name, 'Unknown'), ')') AS detail, p.severity 
            FROM port_finding p 
            JOIN check_run c ON p.check_run_id = c.check_run_id 
            JOIN device d ON c.device_id = d.device_id 
            WHERE d.device_group_id = ? 
            UNION ALL 
            SELECT c.run_timestamp, d.hostname, d.device_id, 'Firewall' AS finding_type, 
                   CONCAT('Profile: ', COALESCE(f.profile, 'Unknown'), ' | Risky Rules: ', f.risky_rule_count) AS detail, 
                   CASE WHEN f.status = 'Warning' THEN 'high' ELSE 'info' END AS severity 
            FROM firewall_finding f 
            JOIN check_run c ON f.check_run_id = c.check_run_id 
            JOIN device d ON c.device_id = d.device_id 
            WHERE d.device_group_id = ? 
            ORDER BY run_timestamp DESC 
            LIMIT 500
        ";
        $stmt = $pdo->prepare($alerts_query);
        $stmt->execute([$user_group_id, $user_group_id]);
        $alerts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $alerts = [];
    }
}

include __DIR__ . '/includes/header.php';
?>

<!-- ========================================================================= -->
<!-- HTML CONTENT - ALERTS DASHBOARD INTERFACE -->
<!-- ========================================================================= -->

<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h2 class="mb-0"><i class="bi bi-bell me-2"></i>Recent Security Alerts</h2>
            <p class="text-muted mb-0 mt-1">Review and prioritize potential security risks on your endpoints</p>
        </div>
        <!-- Dynamic counter reflecting the RLS-filtered dataset -->
        <span class="badge bg-secondary fs-6"><?= count($alerts) ?> Total Alerts</span>
    </div>

    <!-- KPI Summary Cards -->
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card bg-danger text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Critical</h6>
                    <h2 class="fw-bold"><?= number_format($stats['critical_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-warning text-dark shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-black-50 text-uppercase small">High</h6>
                    <h2 class="fw-bold"><?= number_format($stats['high_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-dark text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Medium</h6>
                    <h2 class="fw-bold"><?= number_format($stats['medium_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
    </div>

    <!-- Unified Alert Feed DataTable -->
    <div class="card shadow-sm">
        <div class="card-header bg-white py-3">
            <h5 class="mb-0 text-muted">Unified Alert Feed</h5>
        </div>
        <div class="card-body">
            <?php if (empty($alerts)): ?>
                <div class="text-center py-5">
                    <i class="bi bi-bell-slash display-4 text-muted"></i>
                    <h5 class="mt-3">No Recent Alerts Found</h5>
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
                                // Dynamic severity badge mapping for visual consistency
                                $badge_class = $alert['severity'] === 'critical' ? 'bg-danger' : ($alert['severity'] === 'high' ? 'bg-warning text-dark' : 'bg-dark');
                            ?>
                            <tr>
                                <!-- SR3: Escape all dynamic output to prevent Cross-Site Scripting (XSS) -->
                                <td><small><?= date('d M Y, H:i', strtotime($alert['run_timestamp'])) ?></small></td>
                                <td><strong><?= htmlspecialchars($alert['hostname'] ?? 'Unknown') ?></strong></td>
                                <td><span class="badge bg-info text-dark"><?= htmlspecialchars($alert['finding_type']) ?></span></td>
                                <td><?= htmlspecialchars($alert['detail']) ?></td>
                                <td><span class="badge <?= $badge_class ?>"><?= strtoupper(htmlspecialchars($alert['severity'])) ?></span></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- ========================================================================= -->
<!-- JAVASCRIPT - DATATABLES INITIALIZATION -->
<!-- ========================================================================= -->
<script>
$(document).ready(function() {
    // Initialize Bootstrap Tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) { 
        return new bootstrap.Tooltip(tooltipTriggerEl, { trigger: 'hover', placement: 'auto' }); 
    });

    // Initialize DataTables for the unified alerts feed
    $('#alertsTable').DataTable({ 
        order: [[0, 'desc']], // Default sort by Timestamp (newest first)
        pageLength: 25,
        language: { 
            search: "Search alerts:" 
        } 
    });
});
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>