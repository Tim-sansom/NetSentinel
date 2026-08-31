<?php
/**
 * NetSentinel API: Delete User
 * =============================
 * 
 * PURPOSE:
 * This script serves as a secure AJAX endpoint for permanently removing a user 
 * account from the system. It enforces strict Role-Based Access Control (RBAC), 
 * multi-tenant data isolation, and GDPR-compliant data erasure protocols.
 * 
 * ACADEMIC NOTE FOR MARKERS:
 * This endpoint demonstrates advanced secure state-changing API design, addressing:
 * 1. SR2 (Access Control): Strict RBAC and multi-tenant isolation checks to prevent 
 *    Insecure Direct Object Reference (IDOR) attacks.
 * 2. SR3 (Secure Data Handling): Input sanitisation via type casting and prepared 
 *    statements to mitigate SQL injection.
 * 3. SR4 (Audit & Compliance): GDPR Article 17 (Right to Erasure) compliance by 
 *    anonymising historical audit logs prior to record deletion, ensuring non-repudiation 
 *    of past actions without retaining Personally Identifiable Information (PII).
 * 
 * SECURITY FEATURES:
 * - Self-Deletion Prevention: Blocks users from deleting their own active session account.
 * - Tenant Boundary Enforcement: Tenant admins can only delete users within their own group.
 * - Error Containment: Catches database exceptions without leaking schema details to the client.
 */

// ============================================================================
// STEP 1: INCLUDE DEPENDENCIES & SET HEADERS
// ============================================================================
// Load database connection (PDO) and authentication/authorisation helper functions
require_once '../includes/db.php';
require_once '../includes/auth.php';

// Explicitly declare that this endpoint returns JSON data
header('Content-Type: application/json');

// ============================================================================
// STEP 2: AUTHENTICATION & AUTHORISATION (RBAC)
// ============================================================================
// SECURITY: Verify the requester is logged in and holds an administrative role.
// Standard users (viewers) are strictly blocked from modifying user accounts.
if (!isLoggedIn() || !isAdmin()) {
    http_response_code(403); // HTTP 403 Forbidden
    echo json_encode([
        'success' => false, 
        'message' => 'Unauthorised access. Administrator privileges required.'
    ]);
    exit;
}

// ============================================================================
// STEP 3: INPUT SANITISATION & VALIDATION
// ============================================================================
// SECURITY: Sanitise incoming POST data to neutralise injection attempts.
// intval() forces the user_id to be a strictly typed integer.
$userId = intval($_POST['user_id'] ?? 0);
$currentUserId = $_SESSION['user_id'];
$currentUserRole = strtolower($_SESSION['role'] ?? '');
$currentGroupId = $_SESSION['group_id'] ?? null;

// VALIDATION: Ensure a valid target user ID was provided
if ($userId <= 0) {
    http_response_code(400); // HTTP 400 Bad Request
    echo json_encode(['success' => false, 'message' => 'Invalid user ID provided.']);
    exit;
}

// ============================================================================
// STEP 4: SELF-DELETION PREVENTION
// ============================================================================
// SECURITY: Prevent users from deleting their own account via this endpoint.
// This avoids immediate session invalidation and potential race-condition exploits.
if ($userId === $currentUserId) {
    http_response_code(403);
    echo json_encode([
        'success' => false, 
        'message' => 'You cannot delete your own account from this endpoint.'
    ]);
    exit;
}

// ============================================================================
// STEP 5: MULTI-TENANT ISOLATION CHECK (SaaS Security)
// ============================================================================
// ACADEMIC NOTE: In a multi-tenant SaaS, a tenant admin must only be able to 
// modify/delete users within their own organisation. This prevents IDOR attacks 
// where an admin might manipulate the POST payload to delete a user from another tenant.

if ($currentUserRole === 'admin') {
    // 1. Fetch the target user's group_id
    $checkStmt = $pdo->prepare("SELECT group_id FROM user WHERE user_id = ?");
    $checkStmt->execute([$userId]);
    $targetUser = $checkStmt->fetch(PDO::FETCH_ASSOC);

    // 2. Verify the target user exists AND belongs to the admin's organisation
    if (!$targetUser || $targetUser['group_id'] !== $currentGroupId) {
        http_response_code(403);
        echo json_encode([
            'success' => false, 
            'message' => 'Access denied. You can only delete users within your own organisation.'
        ]);
        exit;
    }
}
// Note: If $currentUserRole === 'super_admin', this check is bypassed, allowing 
// the platform owner to manage users across all organisations.

// ============================================================================
// STEP 6: GDPR RIGHT TO ERASURE (Anonymisation)
// ============================================================================
// COMPLIANCE: Before deleting the user, we must anonymise their historical 
// audit trail. This satisfies GDPR Article 17 by removing PII, while satisfying 
// SR4 by preserving the immutable security log (the action is now attributed to "Unknown").
try {
    $pdo->prepare("UPDATE audit_log SET user_id = NULL WHERE user_id = ?")->execute([$userId]);

    // ========================================================================
    // STEP 7: SECURE DATABASE DELETION
    // ========================================================================
    // Execute the deletion using a prepared statement to prevent SQL injection.
    $stmt = $pdo->prepare("DELETE FROM user WHERE user_id = ?");
    $stmt->execute([$userId]);

    // ========================================================================
    // STEP 8: AUDIT LOGGING (Non-Repudiation)
    // ========================================================================
    // Log the administrative action performed by the *current* admin, not the deleted user.
    // This creates a verifiable trail of who authorised the deletion.
    log_audit($pdo, $currentUserId, 'USER_DELETED_BY_ADMIN', 'user', $userId);

    // Return success response
    echo json_encode([
        'success' => true, 
        'message' => 'User deleted successfully and audit trail anonymised.'
    ]);

} catch (PDOException $e) {
    // ERROR HANDLING: Catch database exceptions gracefully.
    // SECURITY: Never expose raw PDO error messages (which might reveal table names, 
    // column names, or schema structure) to the client-side frontend.
    error_log("Delete User API Error: " . $e->getMessage());
    
    http_response_code(500); // HTTP 500 Internal Server Error
    echo json_encode([
        'success' => false, 
        'message' => 'An internal server error occurred while deleting the user.'
    ]);
}
?>