<?php
/**
 * NetSentinel Recent Alerts Page
 * Displays unified security findings with solid color-coded 
 * severity badges for quick situational awareness.
 */
require_once 'includes/db.php';
require_once 'includes/auth.php';
requireLogin();

$page_title = "Recent Alerts";
require_once 'includes/header.php';

try {
    // 1. Fetch Summary Counts for the top cards
    $stmt = $pdo->query("
        SELECT 
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count
        FROM port_finding
    ");
    $counts = $stmt->fetch(PDO::FETCH_ASSOC);

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
} catch (PDOException $e) {
    $error = "Database error: " . htmlspecialchars($e->getMessage());
    $alerts = [];
    $counts = ['critical_count' => 0, 'high_count' => 0, 'medium_count' => 0];
}
?>
<!-- HTML remains the same. Note: The inline styles with !important on the badges 
     ensure the solid Red/Yellow/Black theme overrides Bootstrap's default pill borders (Fixes D-022). -->
<div class="d-flex justify-content-between align-items-center mb-4">
<!-- ... (rest of your HTML) ... -->