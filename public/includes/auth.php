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
    // Start session if not already started
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    // Check if user is logged in
    if (!isset($_SESSION['user_id'])) {
        // Redirect to login page
        header('Location: login.php');
        exit;
    }
}

/**
 * Ensures the logged-in user has the 'admin' role.
 * Must be called AFTER requireLogin().
 */
function requireAdmin(): void {
    requireLogin(); // Ensure logged in first
    
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
        http_response_code(403);
        die('Access denied. Admin privileges required.');
    }
}

/**
 * Check if the current user has a specific role.
 * 
 * @param string $role The role to check (e.g., 'admin', 'viewer')
 * @return bool
 */
function hasRole(string $role): bool {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    return isset($_SESSION['role']) && $_SESSION['role'] === $role;
}

// ============================================
// 2. TOKEN-BASED AUTH (For API Endpoints)
// ============================================

/**
 * Validates the API token from the agent.
 * Expects token in the "Authorization: Bearer <token>" header.
 * 
 * @param PDO $pdo Database connection
 * @return array|false Returns device info array if valid, false otherwise
 */
function validateApiToken(PDO $pdo): array|false {
    // Get the Authorization header
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
    
    if (empty($authHeader) || !str_starts_with($authHeader, 'Bearer ')) {
        return false;
    }
    
    // Extract the token
    $token = substr($authHeader, 7);
    
    try {
        // Look up the device by API token
        $stmt = $pdo->prepare("
            SELECT device_id, hostname, is_active 
            FROM device 
            WHERE api_token = ? AND is_active = 1
        ");
        $stmt->execute([$token]);
        $device = $stmt->fetch(PDO::FETCH_ASSOC);
        
        return $device ?: false;
        
    } catch (PDOException $e) {
        error_log("API Auth Error: " . $e->getMessage());
        return false;
    }
}

/**
 * Require a valid API token. Exits with 401 if invalid.
 * 
 * @param PDO $pdo Database connection
 * @return array Returns device info array
 */
function requireApiToken(PDO $pdo): array {
    $device = validateApiToken($pdo);
    
    if (!$device) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Unauthorized: Invalid or missing API token']);
        exit;
    }
    
    return $device;
}