<?php
/**
 * NetSentinel Authentication & Authorization
 * Handles both API token validation (for agents) and 
 * Session-based login (for dashboard users).
 */

// ============================================
// 1. SESSION-BASED AUTH (For Dashboard Pages)
// ============================================

/**
 * Ensures a user is logged in via PHP session.
 * If not logged in, redirects to login.php and exits.
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
 */
function requireAdmin(): void {
    requireLogin(); 
    
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
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
    return isset($_SESSION['role']) && $_SESSION['role'] === $role;
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
    // 1. Extract Bearer token
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
    
    if (empty($authHeader) || !str_starts_with($authHeader, 'Bearer ')) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Missing Authorization header']);
        exit;
    }
    
    $token = substr($authHeader, 7);
    $token_hash = hash('sha256', $token); // Hash the incoming token
    
    try {
        // 2. Look up device by HASHED token
        // Using is_active = 1 ensures revoked tokens are rejected
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
                $logStmt = $pdo->prepare("
                    INSERT INTO audit_log (event_type, detail, created_at) 
                    VALUES ('agent_auth_fail', 'Invalid or revoked token presented', NOW())
                ");
                $logStmt->execute();
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
    
    if (!is_array($data) || !isset($data['device_uuid'], $data['checks']) || !is_array($data['checks'])) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Malformed JSON payload']);
        exit;
    }
    
    return $data;
}