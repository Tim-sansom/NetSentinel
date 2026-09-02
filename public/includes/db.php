<?php
/**
 * NetSentinel Database Connection Handler
 * Establishes a secure PDO connection to the MySQL database.
 * 
 * SECURITY NOTE: Credentials are strictly loaded from environment variables.
 * The script fails fast if required credentials are missing, preventing 
 * insecure default fallbacks (OWASP A05: Security Misconfiguration).
 */

// 1. Environment Configuration & Error Reporting
// Only show errors if we are in the development environment (Docker)
if (getenv('NETSENTINEL_ENV') === 'development') {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    // In production, hide errors from users but log them to a file
    error_reporting(0);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
}

// 2. Secure Configuration via Environment Variables
// Fulfils 12-Factor App methodology: credentials are never hardcoded in source control.
$host = getenv('DB_HOST') ?: 'mysql'; // Safe fallback for local Docker network name
$db   = getenv('DB_NAME');
$user = getenv('DB_USER');
$pass = getenv('DB_PASS');
$charset = 'utf8mb4'; // utf8mb4 supports full Unicode (emojis, special chars) safely

// SECURITY: Strict validation to prevent insecure default fallbacks (OWASP A05)
if (empty($db) || empty($user) || empty($pass)) {
    error_log("CRITICAL: Database credentials (DB_NAME, DB_USER, or DB_PASS) are missing from environment variables.");
    http_response_code(500);
    // Generic message to prevent leaking configuration details to the client
    echo json_encode(["status" => "error", "message" => "Critical configuration error: Database credentials missing."]);
    exit;
}

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";

// 3. PDO Security Attributes (CRITICAL for SR3)
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