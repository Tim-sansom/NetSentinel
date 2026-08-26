<?php
/**
 * NetSentinel Logout Handler
 * Securely destroys the user session and clears authentication cookies.
 */

// 1. Start session to access session data
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// 2. Unset all session variables
$_SESSION = array();

// 3. SECURITY: Destroy the session cookie on the client side.
// If cookies are used, set the expiration to a past time to force deletion.
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(), 
        '', 
        time() - 42000,
        $params["path"], 
        $params["domain"],
        $params["secure"], 
        $params["httponly"]
    );
}

// 4. Destroy the session data on the server
session_destroy();

// 5. Redirect to login page
header('Location: login.php');
exit;
?>