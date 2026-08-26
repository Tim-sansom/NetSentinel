<?php
/**
 * NetSentinel User Registration Page
 * Handles new user creation with strict input validation and GDPR data minimization.
 */
require_once 'includes/db.php';
require_once 'includes/audit.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// If already logged in, redirect to dashboard
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // 1. SR3 (Input Validation): Strict server-side validation
    if (empty($username) || empty($email) || empty($password) || empty($confirm_password)) {
        $error = 'All fields are required.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    } elseif ($password !== $confirm_password) {
        $error = 'Passwords do not match.';
    } elseif (strlen($password) < 8) {
        $error = 'Password must be at least 8 characters long.';
    } else {
        try {
            // 2. Check if username or email already exists
            $stmt = $pdo->prepare("SELECT user_id FROM user WHERE username = ? OR email = ?");
            $stmt->execute([$username, $email]);
            
            if ($stmt->fetch()) {
                $error = 'Username or email is already registered.';
            } else {
                // 3. SECURITY: Hash password securely using bcrypt/Argon2
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                
                // 4. GDPR Data Minimization: Only store essential data (username, email, hash).
                // Do not collect DOB, phone numbers, or other unnecessary PII.
                // Default role is 'viewer' to enforce least privilege.
                $stmt = $pdo->prepare("
                    INSERT INTO user (username, email, password_hash, role)
                    VALUES (?, ?, ?, 'viewer')
                ");
                $stmt->execute([$username, $email, $password_hash]);
                
                $new_user_id = (int) $pdo->lastInsertId();
                
                // 5. Audit Log the registration
                log_audit($pdo, $new_user_id, 'USER_REGISTERED', 'user', $new_user_id, ['email' => $email]);
                
                $success = 'Registration successful! You can now <a href="login.php">log in</a>.';
            }
        } catch (PDOException $e) {
            $error = 'Database error. Please try again later.';
            // SECURITY: Log actual error internally, never expose schema to user
            error_log("Registration DB error: " . $e->getMessage());
        }
    }
}

$page_title = "Register";
require_once 'includes/header.php';
?>
<!-- HTML remains exactly the same as your current file -->
<div class="row justify-content-center mt-5">
<!-- ... (rest of your HTML) ... -->