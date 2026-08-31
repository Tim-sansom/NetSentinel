<?php
/**
 * NetSentinel CSV Export Engine
 * Lightweight, memory-efficient streaming export for 
 * Devices, Alerts, Threats, and Audit Logs.
 * 
 * SECURITY NOTE: Implements Row-Level Security (RLS) to ensure tenant admins
 * can only export data relevant to their own organization, preventing mass data leakage.
 */

// 1. Start session FIRST to prevent "headers already sent" errors
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// 2. Include dependencies
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

// 3. Ensure user is logged in (SR2)
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// --- SECURITY: Determine user's access scope ---
$is_super_admin = (strtolower($_SESSION['role'] ?? '') === 'super_admin');
$user_group_id = $_SESSION['group_id'] ?? null;

$type = $_GET['type'] ?? '';

// SECURITY: Sanitize filename to prevent directory traversal or header injection
$filename = "netsentinel_" . preg_replace('/[^a-zA-Z0-9_]/', '', $type) . "_" . date('Y-m-d_His') . ".csv";

// Set headers for CSV download
header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Pragma: no-cache');
header('Expires: 0');

// PERFORMANCE (NFR1): Open php://output stream.
// This streams data directly to the browser row-by-row instead of loading 
// thousands of database rows into PHP memory. Crucial for SME shared hosting limits.
$output = fopen('php://output', 'w');

// Add UTF-8 BOM so Excel opens special characters correctly
fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));

try {
    switch ($type) {
        case 'devices':
            fputcsv($output, ['Device ID', 'Hostname', 'OS Family', 'OS Version', 'Health Status', 'Last Seen']);
            if ($is_super_admin) {
                $stmt = $pdo->query("SELECT device_id, hostname, os_family, os_version, current_health_status, last_seen_at FROM device ORDER BY last_seen_at DESC");
            } else {
                // RLS: Tenant admins only export their own devices
                $stmt = $pdo->prepare("SELECT device_id, hostname, os_family, os_version, current_health_status, last_seen_at FROM device WHERE device_group_id = ? ORDER BY last_seen_at DESC");
                $stmt->execute([$user_group_id]);
            }
            break;
            
        case 'alerts':
            fputcsv($output, ['Timestamp', 'Hostname', 'Type', 'Detail', 'Severity']);
            if ($is_super_admin) {
                $sql = "
                    SELECT c.run_timestamp, d.hostname, 'Port' AS type, CONCAT('Port ', p.port_number, ' (', COALESCE(p.process_name, 'Unknown'), ')') AS detail, p.severity
                    FROM port_finding p JOIN check_run c ON p.check_run_id = c.check_run_id JOIN device d ON c.device_id = d.device_id
                    UNION ALL
                    SELECT c.run_timestamp, d.hostname, 'Firewall', CONCAT('Profile: ', COALESCE(f.profile, 'Unknown')), CASE WHEN f.status = 'Warning' THEN 'high' ELSE 'info' END
                    FROM firewall_finding f JOIN check_run c ON f.check_run_id = c.check_run_id JOIN device d ON c.device_id = d.device_id
                    ORDER BY run_timestamp DESC LIMIT 1000
                ";
                $stmt = $pdo->query($sql);
            } else {
                // RLS: Tenant admins only export alerts for their own devices
                $sql = "
                    SELECT c.run_timestamp, d.hostname, 'Port' AS type, CONCAT('Port ', p.port_number, ' (', COALESCE(p.process_name, 'Unknown'), ')') AS detail, p.severity
                    FROM port_finding p JOIN check_run c ON p.check_run_id = c.check_run_id JOIN device d ON c.device_id = d.device_id
                    WHERE d.device_group_id = ?
                    UNION ALL
                    SELECT c.run_timestamp, d.hostname, 'Firewall', CONCAT('Profile: ', COALESCE(f.profile, 'Unknown')), CASE WHEN f.status = 'Warning' THEN 'high' ELSE 'info' END
                    FROM firewall_finding f JOIN check_run c ON f.check_run_id = c.check_run_id JOIN device d ON c.device_id = d.device_id
                    WHERE d.device_group_id = ?
                    ORDER BY run_timestamp DESC LIMIT 1000
                ";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$user_group_id, $user_group_id]);
            }
            break;
            
        case 'threats':
            // Threats are global intelligence, so no RLS filtering is needed here
            fputcsv($output, ['CVE ID', 'Title', 'Product', 'Severity', 'Date Added']);
            $stmt = $pdo->query("SELECT cve_id, title, product, severity, date_added FROM vulnerability_feed ORDER BY date_added DESC");
            break;

        // Audit Log Export (GDPR Safe + RLS)
        case 'audit':
            fputcsv($output, ['Timestamp', 'User', 'Action', 'Target Type', 'Target ID', 'IP Address']);
            if ($is_super_admin) {
                $stmt = $pdo->query("
                    SELECT al.created_at AS timestamp, COALESCE(u.username, 'Unknown User') as username, al.action, al.target_type, al.target_id, al.ip_address
                    FROM audit_log al
                    LEFT JOIN user u ON al.user_id = u.user_id
                    ORDER BY al.created_at DESC
                ");
            } else {
                // RLS: Tenant admins only export audit logs relevant to their organization
                $stmt = $pdo->prepare("
                    SELECT al.created_at AS timestamp, COALESCE(u.username, 'Unknown User') as username, al.action, al.target_type, al.target_id, al.ip_address
                    FROM audit_log al
                    LEFT JOIN user u ON al.user_id = u.user_id
                    WHERE 
                        (u.group_id = ?)
                        OR (al.target_type = 'device' AND al.target_id IN (SELECT device_id FROM device WHERE device_group_id = ?))
                        OR (al.target_type = 'user' AND al.target_id IN (SELECT user_id FROM user WHERE group_id = ?))
                        OR (al.target_type = 'device_group' AND al.target_id = ?)
                    ORDER BY al.created_at DESC
                ");
                $stmt->execute([$user_group_id, $user_group_id, $user_group_id, $user_group_id]);
            }
            break;
            
        default:
            exit('Invalid export type requested.');
    }

    // Stream the data directly to the browser
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