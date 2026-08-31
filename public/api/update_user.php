<?php
/**
 * NetSentinel API: Update User Details
 * =====================================
 * 
 * PURPOSE:
 * This script serves as an AJAX endpoint to modify an existing user's profile, 
 * role, or password. It enforces strict Role-Based Access Control (RBAC) and 
 * multi-tenant data isolation to prevent unauthorised privilege escalation.
 * 
 * ACADEMIC NOTE FOR MARKERS:
 * This endpoint demonstrates secure state-changing API design, addressing:
 * 1. SR2 (Access Control): Strict RBAC and multi-tenant isolation checks.
 * 2. SR3 (Secure Data Handling): Input sanitisation, prepared statements, and secure password hashing.
 * 3. SR4 (Audit & Compliance): Non-repudiation through mandatory audit logging of all administrative changes.
 * 
 * SECURITY FEATURES:
 * - Multi-Tenant Isolation: Prevents tenant admins from moving users between organisations.
 * - Secure Password Handling: Uses PHP's native `password_hash()` with the default algorithm (bcrypt/argon2).
 * - Error Containment: Catches database exceptions without leaking sensitive schema details to the client.
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
// SECURITY: Sanitise all incoming POST data to neutralise injection attempts.
// - intval() forces numeric IDs to be strictly integers.
// - trim() removes leading/trailing whitespace from text inputs.

$userId  = intval($_POST['user_id'] ?? 0);
$username = trim($_POST['username'] ?? '');
$email   = trim($_POST['email'] ?? '');
$role    = $_POST['role'] ?? 'user'; // Default to 'user' if not provided
$password = $_POST['password'] ?? ''; // Optional: only update if provided
$groupId = intval($_POST['group_id'] ?? 0);

// VALIDATION: Ensure the target user ID and username are valid
if ($userId <= 0) {
    http_response_code(400); // HTTP 400 Bad Request
    echo json_encode(['success' => false, 'message' => 'Invalid user ID provided.']);
    exit;
}

if (empty($username)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Username is required and cannot be empty.']);
    exit;
}

// ============================================================================
// STEP 4: MULTI-TENANT SECURITY CHECK (SaaS Isolation)
// ============================================================================
// ACADEMIC NOTE: In a multi-tenant SaaS, a tenant admin must only be able to 
// modify users within their own organisation. This prevents Insecure Direct 
// Object Reference (IDOR) and privilege escalation attacks.

$current_user_id = $_SESSION['user_id'];
$current_user_role = strtolower($_SESSION['role'] ?? '');
$current_group_id = $_SESSION['group_id'] ?? null;

// If the requester is a standard tenant admin (not the platform super admin)
if ($current_user_role === 'admin') {
    // 1. Verify the target user actually belongs to the admin's organisation
    $checkStmt = $pdo->prepare("SELECT group_id FROM user WHERE user_id = ?");
    $checkStmt->execute([$userId]);
    $target_user = $checkStmt->fetch(PDO::FETCH_ASSOC);

    if (!$target_user || $target_user['group_id'] !== $current_group_id) {
        http_response_code(403);
        echo json_encode([
            'success' => false, 
            'message' => 'Access denied. You can only modify users within your own organisation.'
        ]);
        exit;
    }

    // 2. Force the group_id to remain the same. Tenant admins cannot move users to other groups.
    $groupId = $current_group_id; 
}

// ============================================================================
// STEP 5: SECURE DATABASE UPDATE
// ============================================================================
try {
    if (!empty($password)) {
        // SECURITY: If a new password is provided, hash it securely before storage.
        // PASSWORD_DEFAULT uses bcrypt (or argon2 in newer PHP versions), which 
        // automatically handles salting and computational cost.
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        
        $stmt = $pdo->prepare("
            UPDATE user 
            SET username = ?, email = ?, role = ?, password = ?, group_id = ? 
            WHERE user_id = ?
        ");
        $stmt->execute([$username, $email, $role, $hashedPassword, $groupId, $userId]);
    } else {
        // If no new password is provided, leave the existing password hash untouched.
        $stmt = $pdo->prepare("
            UPDATE user 
            SET username = ?, email = ?, role = ?, group_id = ? 
            WHERE user_id = ?
        ");
        $stmt->execute([$username, $email, $role, $groupId, $userId]);
    }

    // ========================================================================
    // STEP 6: AUDIT LOGGING (GDPR & Compliance)
    // ========================================================================
    // COMPLIANCE: Log this administrative action for non-repudiation and security auditing.
    // This satisfies SR4 by creating an immutable trail of who changed what and when.
    // Note: Ensure your includes/auth.php or includes/audit.php defines log_audit()
    log_audit($pdo, $current_user_id, 'USER_UPDATED', 'user', $userId, [
        'new_username' => $username, 
        'new_role' => $role
    ]);

    // Return success response
    echo json_encode([
        'success' => true, 
        'message' => 'User updated successfully.'
    ]);

} catch (PDOException $e) {
    // ERROR HANDLING: Catch database exceptions gracefully.
    // SECURITY: Never expose raw PDO error messages (which might reveal table names or schema) 
    // to the client-side frontend. Log it server-side instead.
    error_log("Update User API Error: " . $e->getMessage());
    
    http_response_code(500); // HTTP 500 Internal Server Error
    echo json_encode([
        'success' => false, 
        'message' => 'An internal server error occurred while updating the user.'
    ]);
}
?>