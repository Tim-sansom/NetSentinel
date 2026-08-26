<?php
/**
 * NetSentinel Legacy CVE Importer
 * 
 * Imports CVEs from a local JSON file into the cve_watchlist table.
 * Includes strict data sanitization (truncation) to prevent DB overflow.
 */
require_once __DIR__ . '/includes/db.php';

$json_file = __DIR__ . '/../data/cves.json';

if (!file_exists($json_file)) {
    die("Error: cves.json not found. Please create a 'data' folder in the project root and place cves.json inside it.");
}

$json_data = file_get_contents($json_file);
$cves = json_decode($json_data, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    die("Error: Invalid JSON file. " . json_last_error_msg());
}

// Prepare the insert statement
// ON DUPLICATE KEY UPDATE ensures we don't crash if the CVE already exists
$stmt = $pdo->prepare("
    INSERT INTO cve_watchlist (cve_id, title, severity, affected_product, vulnerable_versions, is_kev)
    VALUES (?, ?, ?, ?, ?, 1)
    ON DUPLICATE KEY UPDATE title=VALUES(title)
");

$count = 0;
$errors = 0;

foreach ($cves as $cve) {
    $id = $cve['id'] ?? '';
    
    // Use 'notes' or 'summary' for the title
    $title = $cve['notes'] ?? $cve['summary'] ?? 'No description available';
    $vendor = $cve['vendor'] ?? 'Unknown';
    $product = $cve['product'] ?? 'Unknown';
    $affected_product = $vendor . ' ' . $product;
    
    // DATA SANITIZATION: Truncate title if it's excessively long to prevent DB column overflow
    $title = substr($title, 0, 500);
    
    if (empty($id)) continue;
    
    try {
        $stmt->execute([$id, $title, 'High', $affected_product, 'See vendor advisory']);
        $count++;
    } catch (PDOException $e) {
        $errors++;
    }
}

echo "<h2>Import Complete!</h2>";
echo "<p>Successfully processed <strong>$count</strong> CVEs.</p>";
if ($errors > 0) {
    echo "<p>Skipped $errors duplicates or errors.</p>";
}
echo "<p><a href='dashboard.php'>Go to Dashboard</a></p>";
?>