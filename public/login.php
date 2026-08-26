<?php
/**
 * NetSentinel Login Page
 * Handles user authentication, session initialization, and secure redirection.
 */
require_once 'includes/db.php';

// 1. SECURITY: Start session immediately
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// If already logged in, redirect to dashboard to prevent redundant logins
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Accept either username or email in the first field for better UX
    $login_identifier = trim($_POST['login_identifier'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($login_identifier) || empty($password)) {
        $error = 'Please enter both your username/email and password.';
    } else {
        try {
            // SECURITY (SR3): Prepared statement prevents SQL Injection.
            // Checks against BOTH username and email columns.
            $stmt = $pdo->prepare("SELECT user_id, username, email, password_hash, role FROM user WHERE username = ? OR email = ?");
            $stmt->execute([$login_identifier, $login_identifier]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            // SECURITY (SR2): password_verify() is timing-safe, preventing timing attacks.
            if ($user && password_verify($password, $user['password_hash'])) {
                
                // CRITICAL SECURITY: Regenerate session ID to prevent Session Fixation attacks.
                // This ensures an attacker cannot hijack a pre-existing session ID.
                session_regenerate_id(true);
                
                $_SESSION['user_id'] = $user['user_id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'] ?? 'viewer';
                
                header('Location: dashboard.php');
                exit;
            } else {
                // Generic error message to prevent User Enumeration (don't reveal if user exists)
                $error = 'Invalid credentials.';
            }
        } catch (PDOException $e) {
            $error = 'Database error. Please try again later.';
            // SECURITY: Log actual error internally, never expose schema to user
            error_log("Login DB Error: " . $e->getMessage());
        }
    }
}

$page_title = "Login";
require_once 'includes/header.php';
?>
<!-- HTML remains exactly the same as your current file -->
<div class="row justify-content-center mt-5">
<!-- ... (rest of your HTML) ... -->