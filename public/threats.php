<?php
/**
 * NetSentinel Threat Intelligence Page
 * Displays CISA KEV feed data, RCE/Ransomware KPIs,
 * and CVE details for vulnerability management.
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

$page_title = 'Threat Intelligence';

// Fetch summary stats
// NFR1 (Lightweight): Enforce a strict 12-month window in the SQL query.
// This prevents the dashboard from processing historical data bloat, 
// keeping the page load fast and the database size manageable for SME hosting.
$stats = $pdo->query("
    SELECT 
        COUNT(*) as total,
        SUM(is_rce) as rce_count,
        SUM(ransomware_linked) as ransomware_count,
        SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical_count
    FROM vulnerability_feed
    WHERE date_added >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
")->fetch(PDO::FETCH_ASSOC);

include __DIR__ . '/includes/header.php';
?>
<!-- HTML remains exactly the same as your current file -->
<div class="container-fluid mt-4">
<!-- ... (rest of your HTML) ... -->