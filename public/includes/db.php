<?php
/**
 * NetSentinel Database Connection Handler
 * Establishes a secure PDO connection to the MySQL database.
 */

// 1. Secure Configuration via Environment Variables
// Fulfills 12-Factor App methodology: credentials are never hardcoded in source control.
$host = getenv('DB_HOST') ?: 'mysql';
$db   = getenv('DB_NAME') ?: 'netsentinel';
$user = getenv('DB_USER') ?: 'netsentinel_user';
$pass = getenv('DB_PASS') ?: 'AgentPassword123!';
$charset = 'utf8mb4'; // utf8mb4 supports full Unicode (emojis, special chars) safely

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";

// 2. PDO Security Attributes (CRITICAL for SR3)
$options = [
    // Force PDO to throw exceptions on SQL errors, preventing silent failures
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    // Return associative arrays by default for cleaner code
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    // SECURITY: Disable emulated prepares. This forces MySQL to use true prepared statements,
    // making SQL injection virtually impossible by separating the query structure from the data.
    PDO::ATTR_EMULATE_PREPARES   => false, 
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    // SECURITY: Log the actual error internally for debugging, but NEVER expose it to the client.
    // Exposing PDO errors can leak database schema details to attackers.
    error_log("NetSentinel DB Connection Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Database connection failed"]);
    exit;
}
?>