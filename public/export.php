<?php
// public/export.php
// Lightweight CSV Export Engine for NetSentinel

// 1. Start session FIRST to prevent "headers already sent" errors
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// 2. Include dependencies
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

// 3. Ensure user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$type = $_GET['type'] ?? '';
$filename = "netsentinel_" . $type . "_" . date('Y-m-d_His') . ".csv";

// Set headers for CSV download
header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Pragma: no-cache');
header('Expires: 0');

$output = fopen('php://output', 'w');

// Add UTF-8 BOM so Excel opens special characters correctly
fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));

try {
    switch ($type) {
        case 'devices':
            fputcsv($output, ['Device ID', 'Hostname', 'OS Family', 'OS Version', 'Health Status', 'Last Seen']);
            $stmt = $pdo->query("SELECT device_id, hostname, os_family, os_version, current_health_status, last_seen_at FROM device ORDER BY last_seen_at DESC");
            break;
            
        case 'alerts':
            fputcsv($output, ['Timestamp', 'Hostname', 'Type', 'Detail', 'Severity']);
            $stmt = $pdo->query("
                SELECT c.run_timestamp, d.hostname, 'Port' AS type, CONCAT('Port ', p.port_number, ' (', COALESCE(p.process_name, 'Unknown'), ')') AS detail, p.severity
                FROM port_finding p JOIN check_run c ON p.check_run_id = c.check_run_id JOIN device d ON c.device_id = d.device_id
                UNION ALL
                SELECT c.run_timestamp, d.hostname, 'Firewall', CONCAT('Profile: ', COALESCE(f.profile, 'Unknown')), CASE WHEN f.status = 'Warning' THEN 'high' ELSE 'info' END
                FROM firewall_finding f JOIN check_run c ON f.check_run_id = c.check_run_id JOIN device d ON c.device_id = d.device_id
                ORDER BY run_timestamp DESC LIMIT 1000
            ");
            break;
            
        case 'threats':
            fputcsv($output, ['CVE ID', 'Title', 'Product', 'Severity', 'Date Added']);
            $stmt = $pdo->query("SELECT cve_id, title, product, severity, date_added FROM vulnerability_feed ORDER BY date_added DESC");
            break;

        // NEW: Audit Log Export
        case 'audit':
            fputcsv($output, ['Timestamp', 'User', 'Action', 'Target Type', 'Target ID', 'IP Address']);
            $stmt = $pdo->query("
                SELECT al.created_at AS timestamp, COALESCE(u.username, 'Unknown User') as username, al.action, al.target_type, al.target_id, al.ip_address
                FROM audit_log al
                LEFT JOIN user u ON al.user_id = u.user_id
                ORDER BY al.created_at DESC
            ");
            break;
            
        default:
            exit('Invalid export type requested.');
    }

    // Stream the data directly to the browser (Lightweight NFR1 compliance)
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        fputcsv($output, $row);
    }

} catch (PDOException $e) {
    error_log("Export Error: " . $e->getMessage());
    exit('Database error during export.');
}

fclose($output);
exit;
?>