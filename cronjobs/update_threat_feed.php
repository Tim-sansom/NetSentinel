<?php
/**
 * NetSentinel Threat Feed Updater
 * Fetches the CISA KEV feed, filters for the last 12 months, 
 * flags potential RCEs, and upserts into the vulnerability_feed table.
 * 
 * Designed to run via CLI (cron) only.
 */

// 1. Security: Prevent direct web access
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die("Access denied. This script must be run from the command line.");
}

// 2. Bootstrap Database Connection
// Adjust the path if your cronjobs folder is located elsewhere relative to public/
require_once __DIR__ . '/../html/includes/db.php';

// 3. Configuration
$feed_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
$log_prefix = "[" . date('Y-m-d H:i:s') . "] ";
$one_year_ago = date('Y-m-d', strtotime('-12 months'));

// RCE Keyword Detection Regex
$rce_keywords = '/remote code execution|rce|command injection|arbitrary code|arbitrary commands|code execution|unauthenticated.*execute|execute.*code/i';
$ransomware_keywords = '/Known/i';

echo $log_prefix . "Starting CISA KEV feed update...\n";

// 4. Fetch the JSON Feed (using cURL for better HTTPS reliability in CLI)
$ch = curl_init($feed_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
curl_setopt($ch, CURLOPT_USERAGENT, 'NetSentinel-Cron/1.0');
$json = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($json === false || $http_code !== 200) {
    echo $log_prefix . "ERROR: Failed to fetch feed (HTTP $http_code).\n";
    exit(1);
}

$data = json_decode($json, true);
if (!$data || !isset($data['vulnerabilities'])) {
    echo $log_prefix . "ERROR: Invalid JSON structure.\n";
    exit(1);
}

// 5. Prepare SQL Statement (Upsert)
$stmt = $pdo->prepare("
    INSERT INTO vulnerability_feed 
    (cve_id, title, vendor, product, severity, is_rce, is_kev, ransomware_linked, date_added, due_date, published_date) 
    VALUES (?, ?, ?, ?, 'High', ?, 1, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE 
    title=VALUES(title), 
    vendor=VALUES(vendor), 
    product=VALUES(product), 
    is_rce=VALUES(is_rce), 
    ransomware_linked=VALUES(ransomware_linked), 
    due_date=VALUES(due_date), 
    updated_at=NOW()
");

$inserted = 0;
$updated = 0;
$skipped = 0;

// 6. Process and Insert
foreach ($data['vulnerabilities'] as $item) {
    // Enforce 1-year window to keep DB lightweight
    if ($item['dateAdded'] < $one_year_ago) {
        $skipped++;
        continue;
    }

    $cve_id = $item['cveID'];
    $title = $item['shortDescription'] ?? $item['requiredAction'] ?? 'No description';
    $vendor = $item['vendorProject'] ?? 'Unknown';
    $product = $item['product'] ?? 'Unknown';
    
    // Auto-detect RCE and Ransomware links
    $is_rce = preg_match($rce_keywords, $title) ? 1 : 0;
    $is_ransomware = (isset($item['knownRansomwareCampaignUse']) && $item['knownRansomwareCampaignUse'] === 'Known') ? 1 : 0;

    try {
        $stmt->execute([
            $cve_id, 
            $title, 
            $vendor, 
            $product, 
            $is_rce, 
            $is_ransomware, 
            $item['dateAdded'], 
            $item['dueDate'] ?? null, 
            $item['dateAdded'] // Using dateAdded as published proxy for KEV
        ]);
        
        // rowCount() returns 1 for insert, 2 for update in ON DUPLICATE KEY
        if ($stmt->rowCount() == 1) $inserted++;
        else $updated++;
        
    } catch (PDOException $e) {
        echo $log_prefix . "DB Error on $cve_id: " . $e->getMessage() . "\n";
    }
}

echo $log_prefix . "Update complete. Inserted: $inserted | Updated: $updated | Skipped (older than 12mo): $skipped\n";
exit(0);
?>