<?php
/**
 * NetSentinel User Profile Page
 * Handles password updates, TOTP 2FA enrollment, and personal
 * settings with strict CSRF protection.
 */
require_once 'includes/db.php';
require_once 'includes/auth.php';
require_once 'includes/audit.php';
require_once 'includes/2fa.php';

// SECURITY (SR2): Enforce session validation.
requireLogin();

$user_id = $_SESSION['user_id'];
$message = '';
$message_type = 'success';

// Fetch current user data
$stmt = $pdo->prepare("SELECT username, email, totp_enabled, totp_secret FROM user WHERE user_id = ?");
$stmt->execute([$user_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    session_destroy();
    header('Location: login.php');
    exit;
}

// Handle Form Submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // SECURITY (SR4): Verify CSRF Token for ALL POST requests.
    // Prevents Cross-Site Request Forgery attacks where a malicious site 
    // tries to force the user's browser to submit a form.
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $message = 'Invalid security token. Please refresh and try again.';
        $message_type = 'danger';
    }
    
    // 1. Update Email
    elseif (isset($_POST['update_email'])) {
        $new_email = trim($_POST['email']);
        if (filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
            try {
                $stmt = $pdo->prepare("UPDATE user SET email = ? WHERE user_id = ?");
                $stmt->execute([$new_email, $user_id]);
                log_audit($pdo, $user_id, 'PROFILE_EMAIL_UPDATED', 'user', $user_id);
                $message = 'Email updated successfully.';
                $user['email'] = $new_email;
            } catch (PDOException $e) {
                $message = 'Error updating email. It may already be in use.';
                $message_type = 'danger';
            }
        } else {
            $message = 'Please enter a valid email address.';
            $message_type = 'danger';
        }
    }
    
    // 2. Change Password
    elseif (isset($_POST['update_password'])) {
        $current_pass = $_POST['current_password'];
        $new_pass = $_POST['new_password'];
        $confirm_pass = $_POST['confirm_password'];
        
        $stmt = $pdo->prepare("SELECT password_hash FROM user WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $hash = $stmt->fetchColumn();
        
        // SECURITY: Use timing-safe password_verify() to check the current password.
        if (!password_verify($current_pass, $hash)) {
            $message = 'Current password is incorrect.';
            $message_type = 'danger';
        } elseif (strlen($new_pass) < 8) {
            $message = 'New password must be at least 8 characters.';
            $message_type = 'danger';
        } elseif ($new_pass !== $confirm_pass) {
            $message = 'New passwords do not match.';
            $message_type = 'danger';
        } else {
            // SECURITY: Hash the new password using PHP's default algorithm (currently bcrypt).
            // Never store plain-text passwords in the database.
            $new_hash = password_hash($new_pass, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("UPDATE user SET password_hash = ? WHERE user_id = ?");
            $stmt->execute([$new_hash, $user_id]);
            log_audit($pdo, $user_id, 'PROFILE_PASSWORD_CHANGED', 'user', $user_id);
            $message = 'Password changed successfully.';
        }
    }
    
    // 3. Initialize 2FA Setup (Generate Secret)
    elseif (isset($_POST['init_2fa'])) {
        $secret = LightweightTOTP::generateSecret();
        $_SESSION['2fa_setup_secret'] = $secret;
        $message = 'Scan the QR code below with your authenticator app, then enter the 6-digit code to confirm.';
        $message_type = 'info';
    }
    
    // 4. Verify and Enable 2FA
    elseif (isset($_POST['verify_2fa'])) {
        $code = trim($_POST['totp_code']);
        $secret = $_SESSION['2fa_setup_secret'] ?? '';
        
        // SECURITY: verifyCode uses hash_equals() internally to prevent timing attacks.
        if ($secret && LightweightTOTP::verifyCode($secret, $code)) {
            $stmt = $pdo->prepare("UPDATE user SET totp_enabled = 1, totp_secret = ? WHERE user_id = ?");
            $stmt->execute([$secret, $user_id]);
            unset($_SESSION['2fa_setup_secret']);
            log_audit($pdo, $user_id, '2FA_ENABLED', 'user', $user_id);
            $message = 'Two-Factor Authentication enabled successfully.';
            $user['totp_enabled'] = 1;
        } else {
            $message = 'Invalid code. Please try again or re-scan the QR code.';
            $message_type = 'danger';
        }
    }
    
    // 5. Disable 2FA
    elseif (isset($_POST['disable_2fa'])) {
        $code = trim($_POST['totp_code']);
        if (LightweightTOTP::verifyCode($user['totp_secret'], $code)) {
            $stmt = $pdo->prepare("UPDATE user SET totp_enabled = 0, totp_secret = NULL WHERE user_id = ?");
            $stmt->execute([$user_id]);
            log_audit($pdo, $user_id, '2FA_DISABLED', 'user', $user_id);
            $message = 'Two-Factor Authentication disabled.';
            $user['totp_enabled'] = 0;
        } else {
            $message = 'Invalid 2FA code.';
            $message_type = 'danger';
        }
    }
    
    // 6. Delete Account (GDPR Right to Erasure)
    elseif (isset($_POST['delete_account'])) {
        $confirm_pass = $_POST['confirm_password_delete'];
        $stmt = $pdo->prepare("SELECT password_hash FROM user WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $hash = $stmt->fetchColumn();
        
        if (password_verify($confirm_pass, $hash)) {
            // GDPR COMPLIANCE: Anonymize the audit trail (set user_id to NULL) BEFORE deleting the user.
            // This preserves the security history of the action while removing Personally Identifiable Information (PII).
            $pdo->prepare("UPDATE audit_log SET user_id = NULL WHERE user_id = ?")->execute([$user_id]);
            
            // Delete user record
            $pdo->prepare("DELETE FROM user WHERE user_id = ?")->execute([$user_id]);
            
            log_audit($pdo, null, 'USER_SELF_DELETED', 'user', $user_id);
            
            // Destroy session and redirect
            session_unset();
            session_destroy();
            header('Location: login.php?msg=deleted');
            exit;
        } else {
            $message = 'Password incorrect. Account not deleted.';
            $message_type = 'danger';
        }
    }
}

$page_title = "My Profile";
require_once 'includes/header.php';
?>
<!-- HTML remains exactly the same as your current file -->
<div class="container mt-4">
<!-- ... (rest of your HTML) ... -->