<?php
/**
 * NetSentinel Application Entry Point
 * Handles initial routing based on authentication state.
 */
require_once 'includes/db.php';

// 1. Start session immediately
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// 2. Secure Routing:
// If user is already authenticated, send them straight to the dashboard.
// If not, send them to the login page. This prevents unauthorized access to static pages.
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
} else {
    header('Location: login.php');
}
exit;
?>