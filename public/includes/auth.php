<?php
/**
 * NetSentinel Authentication & Session Management
 * Handles user login, TOTP 2FA verification, session validation,
 * role-based access control (RBAC), and secure session timeouts.
 */

// ============================================
// 0. SESSION HARDENING & COOKIE SECURITY (GDPR/ePrivacy Compliance)
// MUST be set BEFORE session_start() is called anywhere
// ============================================

// Set session configuration BEFORE starting session
if (session_status() === PHP_SESSION_NONE) {
    // 1. Prevent JavaScript access to the session cookie (XSS protection)
    ini_set('session.cookie_httponly', 1);
    
    // 2. Prevent the browser from sending this cookie on cross-site requests (CSRF protection)
    ini_set('session.cookie_samesite', 'Strict');
    
    // 3. Reject uninitialized session IDs to prevent session fixation attacks
    ini_set('session.use_strict_mode', 1);
    
    // 4. Enforce HTTPS for cookies in production, but allow HTTP for local development.
    // This dynamically checks if the request is served over HTTPS (or via a reverse proxy like Cloudflare).
    $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || 
                (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    
    ini_set('session.cookie_secure', $is_https ? 1 : 0);
    
    // NOW start the session with hardened settings
    session_start();
}

// Define inactivity timeout: 15 minutes (900 seconds)
define('SESSION_TIMEOUT', 900); 

require_once __DIR__ . '/audit.php'; 

// ============================================
// 1. SESSION-BASED AUTH (For Dashboard Pages)
// ============================================

/**
 * Ensures a user is logged in via PHP session and hasn't timed out.
 * If not logged in or timed out, redirects to login.php and exits.
 * Fulfills SR2 (Access Control & Session Management).
 */
function requireLogin(): void {
    // Session already started at top of file
    
    // 1. Check for Inactivity Timeout
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT)) {
        // Session has expired due to inactivity
        session_unset();     // Remove all session variables
        session_destroy();   // Destroy the session data on the server
        header('Location: login.php?timeout=1'); // Redirect with a timeout flag
        exit;
    }
    
    // 2. Check if user is actually logged in
    if (!isset($_SESSION['user_id'])) {
        header('Location: login.php');
        exit;
    }
    
    // 3. Update last activity timestamp (Resets the 15-minute timer on every page load/click)
    $_SESSION['last_activity'] = time();
}

/**
 * Ensures the logged-in user has the 'admin' or 'super_admin' role.
 * Must be called AFTER requireLogin().
 * 
 * SECURITY: Uses strtolower() to prevent authorisation bypass if the DB 
 * stores roles as "Admin" instead of "admin" (Fixes D-023).
 */
function requireAdmin(): void {
    requireLogin();
    $role = strtolower($_SESSION['role'] ?? '');
    
    // CRITICAL FIX: Allow both tenant admins and the platform super admin
    if ($role !== 'admin' && $role !== 'super_admin') {
        http_response_code(403);
        die('<div class="container mt-4"><div class="alert alert-danger">Access denied. Administrator privileges required.</div></div>');
    }
}

/**
 * Check if the current user has a specific role.
 */
function hasRole(string $role): bool {
    return isset($_SESSION['role']) && strtolower($_SESSION['role']) === strtolower($role);
}

// ============================================
// 2. TOKEN-BASED AUTH (For API Endpoints - Agents)
// ============================================

/**
 * Validates the API token from the agent and returns the device_uuid.
 * Uses secure hashed token comparison (Fulfils SR2).
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
            // 3. Audit log the failed attempt (Fulfils SR4)
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
 * Fulfils SR3 (Input Validation).
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
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}