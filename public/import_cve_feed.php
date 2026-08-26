<?php
/**
 * NetSentinel CISA KEV Feed Importer (Web Version)
 * 
 * Fetches the Known Exploited Vulnerabilities (KEV) JSON from CISA, 
 * filters for the last 12 months, auto-flags RCE/Ransomware keywords, 
 * and upserts into the vulnerability_feed table.
 */
require_once __DIR__ . '/includes/db.php';

// Path to local JSON fallback (if network fetch fails or for offline testing)
$json_file = __DIR__ . '/../data/cves.json'; 

// SECURITY: Prevent direct execution if not intended (though this is a web script, 
// we still want to ensure it doesn't run during automated scans if not needed).
// Note: For a true cron job, use php_sapi_name() !== 'cli' check.

if (file_exists($json_file)) {
    $json_data = file_get_contents($json_file);
    $cves = json_decode($json_data, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        die("Error: Invalid JSON file structure.");
    }
} else {
    // Fallback: Fetch from CISA API if local file is missing
    $feed_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    $json_data = file_get_contents($feed_url);
    $cves = json_decode($json_data, true);
    
    if (!$cves || !isset($cves['vulnerabilities'])) {
        die("Error: Failed to fetch or parse CISA feed.");
    }
    $cves = $cves['vulnerabilities'];
}

// RCE Keywords to scan the description/notes for (Zero-bloat enrichment)
// This allows the dashboard to flag critical threats without the agent needing to do the work.
$rce_keywords = '/remote code execution|rce|command injection|arbitrary code|code execution|remote command/i';
$ransomware_keywords = '/Known/i'; 

// NFR1 (Performance): Enforce 1-Year Rule to prevent database bloat on low-cost SME hosting.
$one_year_ago = date('Y-m-d', strtotime('-1 year'));

$inserted = 0;
$updated = 0;
$skipped = 0;

// Prepare the upsert statement
// ON DUPLICATE KEY UPDATE ensures idempotency (safe to run multiple times)
$stmt = $pdo->prepare("
    INSERT INTO vulnerability_feed 
    (cve_id, title, vendor, product, severity, is_rce, is_kev, ransomware_linked, date_added, due_date, published_date)
    VALUES (?, ?, ?, ?, 'High', ?, 1, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE 
    title=VALUES(title), vendor=VALUES(vendor), product=VALUES(product), 
    severity=VALUES(severity), is_rce=VALUES(is_rce), ransomware_linked=VALUES(ransomware_linked), 
    due_date=VALUES(due_date), updated_at=NOW()
");

foreach ($cves as $cve) {
    // 1. Enforce 1-Year Rule
    if ($cve['dateAdded'] < $one_year_ago) {
        $skipped++;
        continue;
    }
    
    $cve_id = $cve['id'] ?? $cve['cveID'];
    $title = $cve['notes'] ?? $cve['shortDescription'] ?? 'No description available';
    $vendor = $cve['vendor'] ?? $cve['vendorProject'] ?? 'Unknown';
    $product = $cve['product'] ?? 'Unknown';
    $date_added = $cve['date_added'] ?? $cve['dateAdded'];
    $due_date = $cve['due_date'] ?? $cve['dueDate'] ?? null;
    
    // 2. Auto-Detect RCE via Regex
    $is_rce = preg_match($rce_keywords, $title) ? 1 : 0;
    
    // 3. Auto-Detect Ransomware Link
    $ransomware_val = $cve['ransomware'] ?? $cve['knownRansomwareCampaignUse'] ?? 'Unknown';
    $is_ransomware = preg_match($ransomware_keywords, $ransomware_val) ? 1 : 0;
    
    // 4. Insert/Update
    try {
        $stmt->execute([
            $cve_id, $title, $vendor, $product, 
            $is_rce, $is_ransomware, $date_added, $due_date, $date_added
        ]);
        
        // rowCount() returns 1 for insert, 2 for update in ON DUPLICATE KEY
        if ($stmt->rowCount() == 1) $inserted++;
        else $updated++;
    } catch (PDOException $e) {
        // SECURITY: Log error internally, do not expose DB schema to browser
        error_log("CVE Import Error on $cve_id: " . $e->getMessage());
    }
}

echo "<h2>Import Complete!</h2>";
echo "<p><strong>Inserted:</strong> $inserted new CVEs</p>";
echo "<p><strong>Updated:</strong> $updated existing CVEs</p>";
echo "<p><strong>Skipped (Older than 1 year):</strong> $skipped</p>";
echo "<p><a href='dashboard.php'>Return to Dashboard</a></p>";
?>