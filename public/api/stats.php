<?php
/**
 * NetSentinel Dashboard Statistics Endpoint
 * Provides aggregated dashboard metrics for Chart.js
 * with optimized SQL queries.
 */
header('Content-Type: application/json');

require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';

// SECURITY: Ensure only authenticated dashboard users can fetch stats
if (session_status() === PHP_SESSION_NONE) { session_start(); }
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(["error" => "Unauthorized"]);
    exit;
}

try {
    // 1. KPI Card Metrics (NFR1: Single query for performance)
    $kpiStmt = $pdo->query("
        SELECT 
            COUNT(*) as total_agents,
            SUM(CASE WHEN current_health_status = 'healthy' THEN 1 ELSE 0 END) as secure_agents,
            SUM(CASE WHEN current_health_status != 'healthy' THEN 1 ELSE 0 END) as unhealthy_agents
        FROM device
    ");
    $kpi = $kpiStmt->fetch(PDO::FETCH_ASSOC);

    // 2. Vulnerability Feed Metrics
    $vulnStmt = $pdo->query("
        SELECT 
            COUNT(*) as total_vulns,
            SUM(is_rce) as rce_count,
            SUM(ransomware_linked) as ransomware_count
        FROM vulnerability_feed
    ");
    $vulns = $vulnStmt->fetch(PDO::FETCH_ASSOC);

    // 3. Health Distribution (For Pie Chart)
    $healthStmt = $pdo->query("
        SELECT current_health_status, COUNT(*) as count 
        FROM device 
        GROUP BY current_health_status
    ");
    $health_data = $healthStmt->fetchAll(PDO::FETCH_ASSOC);

    // 4. Recent Alerts Feed (Unified Query)
    $alertStmt = $pdo->query("
        SELECT c.run_timestamp, d.hostname, 'Port' AS type, p.severity
        FROM port_finding p JOIN check_run c ON p.check_run_id = c.check_run_id JOIN device d ON c.device_id = d.device_id
        WHERE p.severity IN ('high', 'critical')
        UNION ALL
        SELECT c.run_timestamp, d.hostname, 'Firewall' AS type, CASE WHEN f.status = 'Warning' THEN 'high' ELSE 'info' END
        FROM firewall_finding f JOIN check_run c ON f.check_run_id = c.check_run_id JOIN device d ON c.device_id = d.device_id
        WHERE f.status = 'Warning'
        ORDER BY run_timestamp DESC LIMIT 5
    ");
    $recent_alerts = $alertStmt->fetchAll(PDO::FETCH_ASSOC);

    // Construct JSON Response
    $response = [
        'agents' => (int)($kpi['total_agents'] ?? 0),
        'secure' => (int)($kpi['secure_agents'] ?? 0),
        'unhealthy' => (int)($kpi['unhealthy_agents'] ?? 0),
        'vulnerabilities' => (int)($vulns['total_vulns'] ?? 0),
        'rce_count' => (int)($vulns['rce_count'] ?? 0),
        'ransomware_count' => (int)($vulns['ransomware_count'] ?? 0),
        'health_data' => $health_data,
        'recent_alerts' => $recent_alerts
    ];

    echo json_encode($response);

} catch (PDOException $e) {
    error_log("Stats API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["error" => "Database connection failed"]);
}
?>