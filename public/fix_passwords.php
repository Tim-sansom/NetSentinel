<?php
/**
 * NetSentinel Password Reset Utility
 * 
 * DEVELOPMENT/TESTING ONLY: This script resets user passwords to a known 
 * state for lab testing. It MUST be deleted from the production environment 
 * to prevent unauthorized access.
 */
require_once 'includes/db.php';

// Generate correct hash for NetSentinel2026!
$password = 'NetSentinel2026!';

// SECURITY: Use PHP's native password_hash with the default algorithm (currently bcrypt).
// This ensures passwords are salted and hashed securely, never stored in plain text.
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
    
    // CRITICAL SECURITY WARNING
    echo "<p style='color:red; font-weight:bold; border: 2px solid red; padding: 10px;'>
          ⚠️ CRITICAL: DELETE THIS FILE IMMEDIATELY AFTER RUNNING IT! 
          Leaving this file on a live server creates a severe security vulnerability.
          </p>";
          
} catch (PDOException $e) {
    // SECURITY: Log actual error internally, show generic message to prevent schema leakage.
    error_log("Password Fix Error: " . $e->getMessage());
    echo "<p style='color:red;'>Error updating passwords. Check server logs.</p>";
}
?>