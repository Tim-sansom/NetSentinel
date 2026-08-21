<?php
require_once __DIR__ . '/includes/db.php';

// Path to your existing CVE Watch JSON file
$json_file = __DIR__ . '/../data/cves.json'; // Adjust path if needed

if (!file_exists($json_file)) {
    die("Error: cves.json not found. Ensure it is in the /data/ directory.");
}

$json_data = file_get_contents($json_file);
$cves = json_decode($json_data, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    die("Error: Invalid JSON file.");
}

// RCE Keywords to scan the description/notes for
$rce_keywords = '/remote code execution|rce|command injection|arbitrary code|code execution|remote command/i';
$ransomware_keywords = '/Known/i'; // Based on your JSON structure where ransomware = "Known"

$one_year_ago = date('Y-m-d', strtotime('-1 year'));
$inserted = 0;
$updated = 0;
$skipped = 0;

// Prepare the upsert statement
$stmt = $pdo->prepare("
    INSERT INTO vulnerability_feed 
    (cve_id, title, vendor, product, severity, is_rce, is_kev, ransomware_linked, date_added, due_date, published_date) 
    VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE 
    title=VALUES(title), vendor=VALUES(vendor), product=VALUES(product), 
    severity=VALUES(severity), is_rce=VALUES(is_rce), ransomware_linked=VALUES(ransomware_linked), 
    due_date=VALUES(due_date), updated_at=NOW()
");

foreach ($cves as $cve) {
    // 1. Enforce 1-Year Rule
    if ($cve['date_added'] < $one_year_ago) {
        $skipped++;
        continue;
    }

    $cve_id = $cve['id'];
    $title = $cve['notes'] ?? 'No description available';
    $vendor = $cve['vendor'] ?? 'Unknown';
    $product = $cve['product'] ?? 'Unknown';
    $date_added = $cve['date_added'];
    $due_date = $cve['due_date'] ?? null;
    
    // 2. Auto-Detect RCE
    $is_rce = preg_match($rce_keywords, $title) ? 1 : 0;
    
    // 3. Auto-Detect Ransomware Link
    $ransomware_val = $cve['ransomware'] ?? 'Unknown';
    $is_ransomware = preg_match($ransomware_keywords, $ransomware_val) ? 1 : 0;

    // 4. Insert/Update
    try {
        $stmt->execute([
            $cve_id, $title, $vendor, $product, 'High', 
            $is_rce, $is_ransomware, $date_added, $due_date, $date_added
        ]);
        
        // Check if it was an insert or update (simplified check)
        if ($stmt->rowCount() == 1) $inserted++;
        else $updated++;
        
    } catch (PDOException $e) {
        echo "Error processing $cve_id: " . $e->getMessage() . "\n";
    }
}

echo "<h2>Import Complete!</h2>";
echo "<p><strong>Inserted:</strong> $inserted new CVEs</p>";
echo "<p><strong>Updated:</strong> $updated existing CVEs</p>";
echo "<p><strong>Skipped (Older than 1 year):</strong> $skipped</p>";
echo "<p><a href='dashboard.php'>Return to Dashboard</a></p>";
?>