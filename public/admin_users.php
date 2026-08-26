<?php
/**
 * NetSentinel User Management Page
 * Admin-only user CRUD operations, role assignment, 
 * and GDPR-compliant Right to Erasure.
 */
require_once 'includes/db.php';
require_once 'includes/auth.php';
require_once 'includes/audit.php';

if (session_status() === PHP_SESSION_NONE) { session_start(); }
requireLogin();

if (!isset($_SESSION['role']) || strtolower($_SESSION['role']) !== 'admin') {
    http_response_code(403);
    die('<div class="container mt-4"><div class="alert alert-danger">Access denied. Admin privileges required.</div></div>');
}

$message = '';
$message_type = 'success';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $message = 'Invalid security token. Please refresh and try again.';
        $message_type = 'danger';
    }
    // ... (Keep your existing Create User logic) ...

    // Delete User (GDPR Right to Erasure)
    elseif (isset($_POST['delete_user'])) {
        $target_user_id = (int) $_POST['user_id'];
        if ($target_user_id === $_SESSION['user_id']) {
            $message = 'You cannot delete your own account from here.';
            $message_type = 'danger';
        } else {
            try {
                // GDPR COMPLIANCE: Anonymize the audit trail (set user_id to NULL) BEFORE deleting the user.
                // This preserves the security history of the action while removing Personally Identifiable Information (PII).
                $pdo->prepare("UPDATE audit_log SET user_id = NULL WHERE user_id = ?")->execute([$target_user_id]);
                
                // Delete the user record
                $stmt = $pdo->prepare("DELETE FROM user WHERE user_id = ?");
                $stmt->execute([$target_user_id]);
                
                log_audit($pdo, $_SESSION['user_id'], 'USER_DELETED_BY_ADMIN', 'user', $target_user_id);
                $message = 'User deleted successfully.';
            } catch (PDOException $e) {
                $message = 'Error deleting user.';
                $message_type = 'danger';
            }
        }
    }
}

// Fetch all users for the table
$stmt = $pdo->query("SELECT user_id, username, email, role, totp_enabled, created_at FROM user ORDER BY created_at DESC");
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

$page_title = "Admin - User Management";
require_once 'includes/header.php';
?>
<!-- HTML remains exactly the same as your current file -->
<div class="container mt-4">
<!-- ... (rest of your HTML) ... -->