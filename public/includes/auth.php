<?php
/**
 * NetSentinel Authentication & Session Management
 * Handles user login, TOTP 2FA verification, session validation,
 * and role-based access control (RBAC).
 */
require_once 'includes/audit.php'; // Ensure audit logging is available

// ============================================
// 1. SESSION-BASED AUTH (For Dashboard Pages)
// ============================================

/**
 * Ensures a user is logged in via PHP session.
 * If not logged in, redirects to login.php and exits.
 * Fulfills SR2 (Access Control).
 */
function requireLogin(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    if (!isset($_SESSION['user_id'])) {
        header('Location: login.php');
        exit;
    }
}

/**
 * Ensures the logged-in user has the 'admin' role.
 * Must be called AFTER requireLogin().
 * 
 * SECURITY: Uses strtolower() to prevent authorization bypass if the DB 
 * stores roles as "Admin" instead of "admin" (Fixes D-023).
 */
function requireAdmin(): void {
    requireLogin();
    if (!isset($_SESSION['role']) || strtolower($_SESSION['role']) !== 'admin') {
        http_response_code(403);
        die('Access denied. Admin privileges required.');
    }
}

/**
 * Check if the current user has a specific role.
 */
function hasRole(string $role): bool {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    return isset($_SESSION['role']) && strtolower($_SESSION['role']) === strtolower($role);
}

// ============================================
// 2. TOKEN-BASED AUTH (For API Endpoints - Agents)
// ============================================

/**
 * Validates the API token from the agent and returns the device_uuid.
 * Uses secure hashed token comparison (Fulfills SR2).
 *
 * @param PDO $pdo Database connection
 * @return string The authenticated device_uuid
 */
function authenticate_api_request(PDO $pdo): string {
    // 1. Extract Bearer token from headers
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
    
    if (empty($authHeader) || !str_starts_with($authHeader, 'Bearer ')) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Missing Authorization header']);
        exit;
    }
    
    $token = substr($authHeader, 7);
    // SECURITY: Hash the incoming token before DB lookup. 
    // We store SHA256 hashes in the DB, not plain text tokens.
    $token_hash = hash('sha256', $token); 
    
    try {
        // 2. Look up device by HASHED token
        // Using is_active = 1 ensures revoked tokens are immediately rejected
        $stmt = $pdo->prepare("
            SELECT device_uuid
            FROM device
            WHERE token_hash = :hash AND is_active = 1
            LIMIT 1
        ");
        $stmt->execute(['hash' => $token_hash]);
        $device = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$device) {
            // 3. Audit log the failed attempt (Fulfills SR4)
            try {
                $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                $logStmt = $pdo->prepare("
                    INSERT INTO audit_log (user_id, action, target_type, details, ip_address)
                    VALUES (NULL, 'AGENT_AUTH_FAIL', 'device', 'Invalid or revoked token presented', :ip)
                ");
                $logStmt->execute(['ip' => $ip_address]);
            } catch (Throwable $e) {
                // Non-fatal: don't break auth flow if audit log fails
            }
            
            http_response_code(401);
            header('Content-Type: application/json');
            echo json_encode(['status' => 'error', 'message' => 'Invalid agent token']);
            exit;
        }
        
        // 4. Return the UUID so submit.php can verify payload integrity
        return $device['device_uuid'];
        
    } catch (PDOException $e) {
        error_log("NetSentinel API Auth Error: " . $e->getMessage());
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Internal server error during auth']);
        exit;
    }
}

/**
 * Validates the incoming JSON payload from the agent.
 * Fulfills SR3 (Input Validation).
 */
function validate_json_payload(): array {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    // Strict validation: Ensure required keys exist and 'checks' is an array
    if (!is_array($data) || !isset($data['device_uuid'], $data['checks']) || !is_array($data['checks'])) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Malformed JSON payload']);
        exit;
    }
    return $data;
}

// ============================================
// 3. CSRF PROTECTION (For Dashboard Forms)
// ============================================

/**
 * Generates and returns a CSRF token for the current session.
 */
function csrf_token(): string {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    if (empty($_SESSION['csrf_token'])) {
        // SECURITY: 32 bytes (256 bits) of cryptographic randomness
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verifies a submitted CSRF token against the session token.
 * Uses hash_equals to prevent timing attacks.
 */
function verify_csrf(string $token): bool {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}