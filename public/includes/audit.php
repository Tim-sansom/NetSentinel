<?php
/**
 * Logs security and audit events to the audit_log table.
 * Note: This file only defines the function. The calling script 
 * must have already included db.php and started the session.
 */
function log_audit(PDO $pdo, ?int $user_id, string $action, ?string $target_type = null, ?int $target_id = null, mixed $details = null): void {
    try {
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_agent = substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 255); 
        
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
        error_log("Audit logging failed: " . $e->getMessage());
    }
}
?>