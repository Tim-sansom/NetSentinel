<?php
/**
 * NetSentinel Audit Logging Helper
 * Provides a centralized function to log administrative and
 * security events to the audit_log table.
 */

/**
 * Logs a security or administrative event to the database.
 * 
 * Designed to fail silently. If the database is down or the log insert fails,
 * the main user action (e.g., logging in or deleting a user) should still succeed.
 * This ensures high availability (NFR1) while attempting to maintain an audit trail.
 *
 * @param PDO $pdo Database connection
 * @param int|null $user_id The ID of the user performing the action (NULL for system/anonymous)
 * @param string $action The action type (e.g., 'LOGIN_SUCCESS', 'USER_DELETED')
 * @param string|null $target_type The type of object affected (e.g., 'user', 'device_group')
 * @param int|null $target_id The ID of the object affected
 * @param mixed $details Additional context (array or string)
 */
function log_audit(PDO $pdo, ?int $user_id, string $action, ?string $target_type = null, ?int $target_id = null, mixed $details = null): void {
    try {
        // Capture client metadata for forensic analysis
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        // SECURITY: Truncate User-Agent to 255 chars to prevent DB column overflow errors.
        $user_agent = substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 255);
        
        // Serialize complex details into JSON for flexible storage in a TEXT column
        $details_json = is_array($details) || is_object($details) ? json_encode($details) : $details;

        $stmt = $pdo->prepare("
            INSERT INTO audit_log (user_id, action, target_type, target_id, details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");
        
        $stmt->execute([
            $user_id,
            $action,
            $target_type,
            $target_id,
            $details_json,
            $ip_address,
            $user_agent
        ]);
    } catch (PDOException $e) {
        // NFR1 (Stability): Log the error internally but do not crash the application.
        // The user's primary action (e.g., password change) must still complete even if auditing fails.
        error_log("Audit logging failed: " . $e->getMessage());
    }
}
?>