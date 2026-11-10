<?php
/**
 * NetSentinel Authentication & Session Management
 * UPDATED: Added Zero-Touch Auto-Registration fallback for new agents.
 */

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.use_strict_mode', 1);
    $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || 
                (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    ini_set('session.cookie_secure', $is_https ? 1 : 0);
    session_start();
}

define('SESSION_TIMEOUT', 900); 
require_once __DIR__ . '/audit.php'; 

function requireLogin(): void {
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT)) {
        session_unset();
        session_destroy();
        header('Location: login.php?timeout=1');
        exit;
    }
    if (!isset($_SESSION['user_id'])) {
        header('Location: login.php');
        exit;
    }
    $_SESSION['last_activity'] = time();
}

function requireAdmin(): void {
    requireLogin();
    $role = strtolower($_SESSION['role'] ?? '');
    if ($role !== 'admin' && $role !== 'super_admin') {
        http_response_code(403);
        die('<div class="container mt-4"><div class="alert alert-danger">Access denied. Administrator privileges required.</div></div>');
    }
}

function hasRole(string $role): bool {
    return isset($_SESSION['role']) && strtolower($_SESSION['role']) === strtolower($role);
}

/**
 * UPDATED: Validates the API token. Returns an array to support auto-registration.
 */
function authenticate_api_request(PDO $pdo, string $payload_uuid = ''): array {
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
    
    if (empty($authHeader) || !str_starts_with($authHeader, 'Bearer ')) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Missing Authorization header']);
        exit;
    }
    
    $token = substr($authHeader, 7);
    $token_hash = hash('sha256', $token); 
    
    try {
        $stmt = $pdo->prepare("SELECT device_uuid, is_active FROM device WHERE token_hash = :hash LIMIT 1");
        $stmt->execute(['hash' => $token_hash]);
        $device = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // 1. Existing Device: Validate token
        if ($device) {
            if ($device['is_active'] != 1) {
                http_response_code(401);
                echo json_encode(['status' => 'error', 'message' => 'Device token has been revoked']);
                exit;
            }
            return ['device_uuid' => $device['device_uuid'], 'is_new' => false, 'token' => $token];
        }
        
        // 2. ZERO-TOUCH AUTO-REGISTRATION FALLBACK
        // If token not found, validate that the payload provides a properly formatted new UUID.
        if (empty($payload_uuid) || !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $payload_uuid)) {
            http_response_code(401);
            echo json_encode(['status' => 'error', 'message' => 'Invalid token and missing/invalid new device UUID']);
            exit;
        }
        
        // Log the auto-registration attempt for security auditing
        try {
            $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $logStmt = $pdo->prepare("INSERT INTO audit_log (user_id, action, target_type, details, ip_address) VALUES (NULL, 'DEVICE_AUTO_REGISTER', 'device', :uuid, :ip)");
            $logStmt->execute(['uuid' => $payload_uuid, 'ip' => $ip_address]);
        } catch (Throwable $e) { /* Ignore audit log failures */ }
        
        // Allow the new device to proceed. submit.php will handle the database upsert.
        return ['device_uuid' => $payload_uuid, 'is_new' => true, 'token' => $token];
        
    } catch (PDOException $e) {
        error_log("NetSentinel API Auth Error: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Internal server error during auth']);
        exit;
    }
}

function validate_json_payload(): array {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    
    if (!is_array($data) || !isset($data['device_uuid'], $data['checks']) || !is_array($data['checks'])) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Malformed JSON payload']);
        exit;
    }
    return $data;
}

function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf(string $token): bool {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}