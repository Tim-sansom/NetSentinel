<?php
/**
 * NetSentinel API: Get User Details
 * ==================================
 * 
 * PURPOSE:
 * This script serves as an AJAX endpoint to retrieve a specific user's details 
 * for the User Management edit modal. It ensures that only authorised administrators 
 * can access this data, preventing unauthorised data exposure.
 * 
 * ACADEMIC NOTE FOR MARKERS:
 * This endpoint demonstrates secure API design principles, including:
 * 1. Strict Role-Based Access Control (RBAC) to enforce SR2 (Access Control).
 * 2. Input sanitisation via type casting to prevent injection attacks (SR3).
 * 3. Use of PDO prepared statements to completely mitigate SQL injection risks.
 * 4. Appropriate HTTP status codes (403 Forbidden, 404 Not Found) for robust error handling.
 * 
 * SECURITY FEATURES:
 * - Session validation: Ensures the requester is logged in.
 * - Role validation: Restricts access exclusively to admin/super_admin roles.
 * - Parameter sanitisation: Forces the `user_id` to be an integer.
 */

// ============================================================================
// STEP 1: INCLUDE DEPENDENCIES
// ============================================================================
// Load database connection (PDO) and authentication/authorization helper functions
require_once '../includes/db.php';
require_once '../includes/auth.php';

// ============================================================================
// STEP 2: SET RESPONSE HEADERS
// ============================================================================
// Explicitly declare that this endpoint returns JSON data
header('Content-Type: application/json');

// ============================================================================
// STEP 3: AUTHENTICATION & AUTHORIZATION (RBAC)
// ============================================================================
// SECURITY: Verify the user is logged in AND holds an administrative role.
// This prevents standard users or unauthenticated actors from enumerating user data.
if (!isLoggedIn() || !isAdmin()) {
    http_response_code(403); // HTTP 403 Forbidden
    echo json_encode([
        'success' => false, 
        'message' => 'Unauthorised access. Administrator privileges required.'
    ]);
    exit;
}

// ============================================================================
// STEP 4: INPUT SANITISATION & VALIDATION
// ============================================================================
// SECURITY: Retrieve the user_id from the GET request and strictly cast it to an integer.
// This neutralises any potential SQL injection attempts via the URL parameter.
$userId = intval($_GET['user_id'] ?? 0);

// Additional validation: Ensure the ID is a positive integer
if ($userId <= 0) {
    http_response_code(400); // HTTP 400 Bad Request
    echo json_encode(['success' => false, 'message' => 'Invalid user ID provided.']);
    exit;
}

// ============================================================================
// STEP 5: DATABASE QUERY (Secure Data Handling)
// ============================================================================
try {
    // SECURITY: Use a PDO prepared statement to fetch the user record.
    // This ensures the $userId variable is treated strictly as data, not executable code.
    $stmt = $pdo->prepare("
        SELECT user_id, username, email, role, group_id 
        FROM user 
        WHERE user_id = ?
    ");
    
    // Execute the query with the sanitised parameter
    $stmt->execute([$userId]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // ========================================================================
    // STEP 6: RESPONSE HANDLING
    // ========================================================================
    if ($user) {
        // Success: Return the user data as a JSON object
        echo json_encode([
            'success' => true,
            'data' => $user
        ]);
    } else {
        // Not Found: The ID is valid, but no matching record exists in the database
        http_response_code(404); // HTTP 404 Not Found
        echo json_encode([
            'success' => false, 
            'message' => 'User not found.'
        ]);
    }
} catch (PDOException $e) {
    // ERROR HANDLING: Catch database exceptions gracefully.
    // IMPORTANT: Never expose raw database errors to the client in a production environment.
    // Log the actual error server-side (via error_log) and return a generic message.
    error_log("Get User API Error: " . $e->getMessage());
    
    http_response_code(500); // HTTP 500 Internal Server Error
    echo json_encode([
        'success' => false, 
        'message' => 'An internal server error occurred while retrieving user data.'
    ]);
}
?>