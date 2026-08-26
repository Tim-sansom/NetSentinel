<?php
/**
 * NetSentinel Device Detail Page
 * Shows historical check runs, findings, and telemetry
 * trends for a specific endpoint.
 */
require_once 'includes/db.php';
require_once 'includes/auth.php';

// SECURITY (SR2): Enforce session validation.
requireLogin();

// Get device ID from URL and sanitize
$device_id = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT);
if (!$device_id) {
    header('Location: devices.php');
    exit;
}

$page_title = "Device Details";
require_once 'includes/header.php';

try {
    // 1. Fetch Device Info
    $stmt = $pdo->prepare("SELECT * FROM device WHERE device_id = ?");
    $stmt->execute([$device_id]);
    $device = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$device) {
        echo '<div class="alert alert-danger">Device not found.</div>';
        require_once 'includes/footer.php';
        exit;
    }

    // 2. Fetch latest Architecture from system_finding
    $stmt = $pdo->prepare("
        SELECT sf.architecture
        FROM system_finding sf
        JOIN check_run c ON sf.check_run_id = c.check_run_id
        WHERE c.device_id = ?
        ORDER BY c.run_timestamp DESC
        LIMIT 1
    ");
    $stmt->execute([$device_id]);
    $latest_sys = $stmt->fetch(PDO::FETCH_ASSOC);
    $architecture = $latest_sys['architecture'] ?? 'N/A';

    // 3. Fetch Latency Data
    $stmt = $pdo->prepare("
        SELECT c.run_timestamp, l.latency_ms
        FROM check_run c
        JOIN latency_finding l ON c.check_run_id = l.check_run_id
        WHERE c.device_id = ?
        ORDER BY c.run_timestamp ASC
        LIMIT 50
    ");
    $stmt->execute([$device_id]);
    $latency_data = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // 4. Fetch Recent Findings (Port, Firewall, AND Patch)
    // PERFORMANCE (NFR1): Uses UNION ALL to merge three different finding tables 
    // into a single chronological feed. This reduces database round-trips and 
    // keeps the dashboard lightweight, even for devices with thousands of historical checks.
    $stmt = $pdo->prepare("
        SELECT 'Port' as type,
        CONCAT('Port ', p.port_number, ' (', COALESCE(p.process_name, 'Unknown'), ')') as detail,
        p.severity,
        c.run_timestamp
        FROM port_finding p
        JOIN check_run c ON p.check_run_id = c.check_run_id
        WHERE c.device_id = ?
        UNION ALL
        SELECT 'Firewall' as type,
        CONCAT('Profile: ', COALESCE(f.profile, 'Unknown')) as detail,
        CASE WHEN f.status = 'fail' THEN 'high' ELSE 'info' END as severity,
        c.run_timestamp
        FROM firewall_finding f
        JOIN check_run c ON f.check_run_id = c.check_run_id
        WHERE c.device_id = ?
        UNION ALL
        SELECT 'Patch' as type,
        CONCAT('Critical Pending: ', p.missing_critical_count, ' | Important: ', p.missing_important_count) as detail,
        CASE WHEN p.missing_critical_count > 0 THEN 'high' WHEN p.missing_important_count > 0 THEN 'medium' ELSE 'info' END as severity,
        c.run_timestamp
        FROM patch_finding p
        JOIN check_run c ON p.check_run_id = c.check_run_id
        WHERE c.device_id = ?
        ORDER BY run_timestamp DESC
        LIMIT 50
    ");
    $stmt->execute([$device_id, $device_id, $device_id]);
    $findings = $stmt->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    error_log("Device Detail Error: " . $e->getMessage());
    $error = "Database error loading device details.";
}
?>
<!-- HTML remains exactly the same as your current file -->
<nav aria-label="breadcrumb">
<!-- ... (rest of your HTML) ... -->