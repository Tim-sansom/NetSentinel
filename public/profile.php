<?php
/**
 * NetSentinel User Profile Page
 * Handles password updates, TOTP 2FA enrolment, and personal
 * settings with strict CSRF protection.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/audit.php';
require_once __DIR__ . '/includes/2fa.php';

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
            // GDPR COMPLIANCE: Anonymize the audit trail BEFORE deleting the user.
            $pdo->prepare("UPDATE audit_log SET user_id = NULL WHERE user_id = ?")->execute([$user_id]);
            
            // Delete user record
            $pdo->prepare("DELETE FROM user WHERE user_id = ?")->execute([$user_id]);
            
            log_audit($pdo, null, 'USER_SELF_DELETED', 'user', $user_id);
            
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
require_once __DIR__ . '/includes/header.php';
?>

<div class="container mt-4">
    <div class="row justify-content-center">
        <div class="col-lg-8">
            
            <!-- Page Header -->
            <div class="d-flex justify-content-between align-items-center mb-4">
                <div>
                    <h2 class="mb-0">
                        <i class="bi bi-person-circle"></i> My Profile
                        <i class="bi bi-question-circle text-muted ms-2" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Manage your account details, security settings, and privacy preferences"
                           style="cursor: help; font-size: 0.6em; vertical-align: middle;"></i>
                    </h2>
                    <p class="text-muted mb-0 mt-1">Keep your contact information and security credentials up to date</p>
                </div>
            </div>

            <!-- Info Banner - What is this page? -->
            <div class="alert alert-info d-flex align-items-start mb-4" role="alert">
                <i class="bi bi-info-circle-fill me-3 mt-1 fs-5"></i>
                <div>
                    <h6 class="alert-heading mb-2">What is this page?</h6>
                    <p class="mb-2 small">
                        This page allows you to manage your personal account settings and security preferences. 
                        We highly recommend enabling Two-Factor Authentication (2FA) to protect your account from unauthorized access.
                    </p>
                    <button class="btn btn-sm btn-link p-0 mt-2" type="button" data-bs-toggle="collapse" data-bs-target="#profileHelp" aria-expanded="false">
                        Show security & privacy details
                    </button>
                    <div class="collapse mt-2" id="profileHelp">
                        <div class="card card-body bg-light small">
                            <p class="mb-2"><strong>Security & Privacy Features:</strong></p>
                            <ul class="mb-0">
                                <li><strong>Two-Factor Authentication (2FA):</strong> Adds a time-based, 6-digit code requirement to your login process, preventing access even if your password is compromised.</li>
                                <li><strong>GDPR Right to Erasure:</strong> If you choose to delete your account, your personal data is permanently removed. However, your historical actions in the Audit Logs are preserved and anonymized (shown as "Unknown User") to maintain a complete, tamper-proof security trail for the organization.</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <?php if ($message): ?>
                <div class="alert alert-<?= htmlspecialchars($message_type) ?> alert-dismissible fade show" role="alert">
                    <?= htmlspecialchars($message) ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            <?php endif; ?>

            <!-- Account Settings Card -->
            <div class="card shadow-sm mb-4">
                <div class="card-header bg-white py-3">
                    <h5 class="mb-0">
                        <i class="bi bi-envelope"></i> Account Settings
                        <i class="bi bi-question-circle text-muted ms-2" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Update your contact email address"
                           style="cursor: help;"></i>
                    </h5>
                </div>
                <div class="card-body">
                    <form method="POST" action="profile.php">
                        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                        <input type="hidden" name="update_email" value="1">
                        
                        <div class="mb-3">
                            <label for="username" class="form-label">
                                Username
                                <i class="bi bi-question-circle text-muted ms-1" 
                                   data-bs-toggle="tooltip" 
                                   data-bs-title="Your unique login identifier. This cannot be changed after account creation."
                                   style="cursor: help;"></i>
                            </label>
                            <input type="text" class="form-control bg-light" id="username" value="<?= htmlspecialchars($user['username']) ?>" disabled>
                        </div>
                        
                        <div class="mb-3">
                            <label for="email" class="form-label">
                                Email Address
                                <i class="bi bi-question-circle text-muted ms-1" 
                                   data-bs-toggle="tooltip" 
                                   data-bs-title="Used for account recovery and system notifications."
                                   style="cursor: help;"></i>
                            </label>
                            <input type="email" class="form-control" id="email" name="email" value="<?= htmlspecialchars($user['email']) ?>" required>
                        </div>
                        
                        <button type="submit" class="btn btn-primary" 
                                data-bs-toggle="tooltip" 
                                data-bs-title="Save your new email address">
                            Update Email
                        </button>
                    </form>
                </div>
            </div>

            <!-- Security Settings Card -->
            <div class="card shadow-sm mb-4">
                <div class="card-header bg-white py-3">
                    <h5 class="mb-0">
                        <i class="bi bi-shield-lock"></i> Change Password
                        <i class="bi bi-question-circle text-muted ms-2" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Update your login credentials"
                           style="cursor: help;"></i>
                    </h5>
                </div>
                <div class="card-body">
                    <form method="POST" action="profile.php">
                        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                        <input type="hidden" name="update_password" value="1">
                        
                        <div class="mb-3">
                            <label for="current_password" class="form-label">Current Password</label>
                            <input type="password" class="form-control" id="current_password" name="current_password" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="new_password" class="form-label">
                                New Password
                                <i class="bi bi-question-circle text-muted ms-1" 
                                   data-bs-toggle="tooltip" 
                                   data-bs-title="Must be at least 8 characters long. We recommend using a mix of letters, numbers, and symbols."
                                   style="cursor: help;"></i>
                            </label>
                            <input type="password" class="form-control" id="new_password" name="new_password" minlength="8" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="confirm_password" class="form-label">Confirm New Password</label>
                            <input type="password" class="form-control" id="confirm_password" name="confirm_password" minlength="8" required>
                        </div>
                        
                        <button type="submit" class="btn btn-warning text-dark"
                                data-bs-toggle="tooltip" 
                                data-bs-title="Update your password">
                            Change Password
                        </button>
                    </form>
                </div>
            </div>

            <!-- 2FA Settings Card -->
            <div class="card shadow-sm mb-4">
                <div class="card-header bg-white py-3 d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">
                        <i class="bi bi-phone"></i> Two-Factor Authentication (2FA)
                        <i class="bi bi-question-circle text-muted ms-2" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Add an extra layer of security using an authenticator app"
                           style="cursor: help;"></i>
                    </h5>
                    <?php if ($user['totp_enabled']): ?>
                        <span class="badge bg-success" 
                              data-bs-toggle="tooltip" 
                              data-bs-title="2FA is active. You will be prompted for a 6-digit code on every login."
                              style="cursor: help;">
                            Enabled
                        </span>
                    <?php else: ?>
                        <span class="badge bg-secondary" 
                              data-bs-toggle="tooltip" 
                              data-bs-title="2FA is disabled. It is highly recommended to enable this for your security."
                              style="cursor: help;">
                            Disabled
                        </span>
                    <?php endif; ?>
                </div>
                <div class="card-body">
                    <?php if (!$user['totp_enabled'] && isset($_SESSION['2fa_setup_secret'])): ?>
                        <!-- Step 2: Verify Code -->
                        <div class="alert alert-info">
                            <p class="mb-2">Enter the 6-digit code from your authenticator app to confirm setup:</p>
                            <div class="bg-white p-3 d-inline-block border rounded mb-3">
                                <small class="text-muted d-block mb-1">Manual Setup Key:</small>
                                <code><?= htmlspecialchars($_SESSION['2fa_setup_secret']) ?></code>
                            </div>
                            <form method="POST" action="profile.php" class="mt-3">
                                <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                <input type="hidden" name="verify_2fa" value="1">
                                <div class="input-group" style="max-width: 300px;">
                                    <input type="text" class="form-control" name="totp_code" placeholder="6-digit code" maxlength="6" pattern="\d{6}" required
                                           data-bs-toggle="tooltip" data-bs-title="Enter the current 6-digit code from your app">
                                    <button type="submit" class="btn btn-success">Verify & Enable</button>
                                </div>
                            </form>
                        </div>
                    <?php elseif (!$user['totp_enabled']): ?>
                        <!-- Step 1: Initialize -->
                        <p class="text-muted mb-3">Add an extra layer of security to your account by enabling 2FA. You will need an authenticator app like Google Authenticator or Authy.</p>
                        <form method="POST" action="profile.php">
                            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                            <input type="hidden" name="init_2fa" value="1">
                            <button type="submit" class="btn btn-outline-primary"
                                    data-bs-toggle="tooltip" 
                                    data-bs-title="Generate a new 2FA secret and QR code">
                                Setup 2FA
                            </button>
                        </form>
                    <?php else: ?>
                        <!-- Disable 2FA -->
                        <p class="text-muted mb-3">2FA is currently active. To disable it, please enter a valid 6-digit code from your authenticator app to confirm your identity.</p>
                        <form method="POST" action="profile.php" class="mt-3">
                            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                            <input type="hidden" name="disable_2fa" value="1">
                            <div class="input-group" style="max-width: 300px;">
                                <input type="text" class="form-control" name="totp_code" placeholder="6-digit code" maxlength="6" pattern="\d{6}" required
                                       data-bs-toggle="tooltip" data-bs-title="Enter the current 6-digit code from your app">
                                <button type="submit" class="btn btn-outline-danger"
                                        data-bs-toggle="tooltip" 
                                        data-bs-title="Remove 2FA protection from your account">
                                    Disable 2FA
                                </button>
                            </div>
                        </form>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Danger Zone Card -->
            <div class="card shadow-sm border-danger mb-4">
                <div class="card-header bg-danger text-white py-3">
                    <h5 class="mb-0">
                        <i class="bi bi-exclamation-triangle"></i> Danger Zone
                        <i class="bi bi-question-circle text-white-50 ms-2" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Irreversible account deletion and data removal"
                           style="cursor: help;"></i>
                    </h5>
                </div>
                <div class="card-body">
                    <p class="text-muted mb-3">
                        Once you delete your account, there is no going back. This action is irreversible and complies with the 
                        <strong>GDPR Right to Erasure</strong> by permanently removing your personal data and anonymizing your historical audit logs.
                    </p>
                    <form method="POST" action="profile.php" onsubmit="return confirm('Are you absolutely sure you want to delete your account? This action cannot be undone and will anonymize your audit trail.');">
                        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                        <input type="hidden" name="delete_account" value="1">
                        
                        <div class="mb-3">
                            <label for="confirm_password_delete" class="form-label">
                                Enter your current password to confirm deletion
                                <i class="bi bi-question-circle text-muted ms-1" 
                                   data-bs-toggle="tooltip" 
                                   data-bs-title="Required to verify your identity before permanent deletion."
                                   style="cursor: help;"></i>
                            </label>
                            <input type="password" class="form-control" id="confirm_password_delete" name="confirm_password_delete" required>
                        </div>
                        
                        <button type="submit" class="btn btn-danger"
                                data-bs-toggle="tooltip" 
                                data-bs-title="Permanently delete this account and anonymize audit logs">
                            Delete My Account
                        </button>
                    </form>
                </div>
            </div>

        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    // Initialize Bootstrap Tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            trigger: 'hover',
            placement: 'auto'
        })
    })
});
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>