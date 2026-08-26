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
// ARCHITECTURE: Uses cr.run_timestamp instead of lf.created_at because log_finding 
// inherits its temporal data from the parent check_run table to save DB space.
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
// PERFORMANCE: Uses UNION ALL to merge log and port findings into a single query, 
// reducing database round-trips and keeping the dashboard lightweight (NFR1).
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
<!-- HTML/JS remains exactly the same as your current file -->
<div class="container-fluid mt-4">
<!-- ... (rest of your HTML) ... -->