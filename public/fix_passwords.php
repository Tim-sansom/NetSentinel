<?php
require_once 'includes/db.php';

// Generate correct hash for NetSentinel2026!
$password = 'NetSentinel2026!';
$hash = password_hash($password, PASSWORD_DEFAULT);

echo "<h2>Updating passwords...</h2>";
echo "<p>Generating hash for: <code>$password</code></p>";
echo "<p>Hash: <code>$hash</code></p>";

try {
    // Update admin user
    $stmt = $pdo->prepare("UPDATE user SET password_hash = ? WHERE username = 'admin'");
    $stmt->execute([$hash]);
    echo "<p>✅ Updated admin user</p>";
    
    // Update viewer user
    $stmt = $pdo->prepare("UPDATE user SET password_hash = ? WHERE username = 'viewer'");
    $stmt->execute([$hash]);
    echo "<p>✅ Updated viewer user</p>";
    
    echo "<h3>Done! You can now log in with:</h3>";
    echo "<ul>";
    echo "<li><strong>Username:</strong> admin | <strong>Password:</strong> NetSentinel2026!</li>";
    echo "<li><strong>Username:</strong> viewer | <strong>Password:</strong> NetSentinel2026!</li>";
    echo "<li><strong>Email:</strong> admin@netsentinel.local | <strong>Password:</strong> NetSentinel2026!</li>";
    echo "</ul>";
    
    echo "<p style='color:red;'><strong>⚠️ IMPORTANT: Delete this file after running it!</strong></p>";
    
} catch (PDOException $e) {
    echo "<p style='color:red;'>Error: " . $e->getMessage() . "</p>";
}
?>