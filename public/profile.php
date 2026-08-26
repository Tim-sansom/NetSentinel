<?php
require_once 'includes/db.php';
require_once 'includes/auth.php';
require_once 'includes/audit.php';
require_once 'includes/2fa.php';

// Ensure user is logged in
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
    // 1. Verify CSRF Token for all POST requests
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $message = 'Invalid security token. Please refresh and try again.';
        $message_type = 'danger';
    } 
    // 2. Update Email
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
    // 3. Change Password
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
    // 4. Initialize 2FA Setup (Generate Secret)
    elseif (isset($_POST['init_2fa'])) {
        $secret = LightweightTOTP::generateSecret();
        $_SESSION['2fa_setup_secret'] = $secret;
        $message = 'Scan the QR code below with your authenticator app, then enter the 6-digit code to confirm.';
        $message_type = 'info';
    } 
    // 5. Verify and Enable 2FA
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
    // 6. Disable 2FA
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
    // 7. Delete Account (GDPR Right to Erasure)
    elseif (isset($_POST['delete_account'])) {
        $confirm_pass = $_POST['confirm_password_delete'];
        $stmt = $pdo->prepare("SELECT password_hash FROM user WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $hash = $stmt->fetchColumn();

        if (password_verify($confirm_pass, $hash)) {
            // Anonymize audit logs before deletion
            $pdo->prepare("UPDATE audit_log SET user_id = NULL WHERE user_id = ?")->execute([$user_id]);
            
            // Delete user
            $pdo->prepare("DELETE FROM user WHERE user_id = ?")->execute([$user_id]);
            
            log_audit($pdo, null, 'USER_SELF_DELETED', 'user', $user_id);
            
            // Destroy session
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

<div class="container mt-4">
    <h2 class="mb-4">My Profile</h2>

    <?php if ($message): ?>
        <div class="alert alert-<?= $message_type ?> alert-dismissible fade show" role="alert">
            <?= htmlspecialchars($message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>

    <div class="row g-4">
        <!-- Column 1: Account Details & Password -->
        <div class="col-lg-6">
            <!-- Update Email -->
            <div class="card mb-4 shadow-sm">
                <div class="card-header bg-white"><h5 class="mb-0">Account Details</h5></div>
                <div class="card-body">
                    <p class="text-muted mb-3"><strong>Username:</strong> <?= htmlspecialchars($user['username']) ?> <span class="badge bg-secondary"><?= htmlspecialchars($_SESSION['role']) ?></span></p>
                    <form method="POST" action="profile.php">
                        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                        <div class="mb-3">
                            <label for="email" class="form-label">Email Address</label>
                            <input type="email" class="form-control" id="email" name="email" value="<?= htmlspecialchars($user['email']) ?>" required>
                        </div>
                        <button type="submit" name="update_email" class="btn btn-primary">Update Email</button>
                    </form>
                </div>
            </div>

            <!-- Change Password -->
            <div class="card shadow-sm">
                <div class="card-header bg-white"><h5 class="mb-0">Change Password</h5></div>
                <div class="card-body">
                    <form method="POST" action="profile.php">
                        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                        <div class="mb-3">
                            <label for="current_password" class="form-label">Current Password</label>
                            <input type="password" class="form-control" id="current_password" name="current_password" required>
                        </div>
                        <div class="mb-3">
                            <label for="new_password" class="form-label">New Password (min 8 chars)</label>
                            <input type="password" class="form-control" id="new_password" name="new_password" minlength="8" required>
                        </div>
                        <div class="mb-3">
                            <label for="confirm_password" class="form-label">Confirm New Password</label>
                            <input type="password" class="form-control" id="confirm_password" name="confirm_password" minlength="8" required>
                        </div>
                        <button type="submit" name="update_password" class="btn btn-warning">Change Password</button>
                    </form>
                </div>
            </div>
        </div>

        <!-- Column 2: 2FA & Danger Zone -->
        <div class="col-lg-6">
            <!-- 2FA Management -->
            <div class="card mb-4 shadow-sm">
                <div class="card-header bg-white"><h5 class="mb-0">Two-Factor Authentication (2FA)</h5></div>
                <div class="card-body">
                    <?php if ($user['totp_enabled']): ?>
                        <p class="text-success fw-bold">2FA is currently <u>ENABLED</u>.</p>
                        <form method="POST" action="profile.php">
                            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                            <div class="mb-3">
                                <label for="disable_totp_code" class="form-label">Enter 6-digit code to disable</label>
                                <input type="text" class="form-control" id="disable_totp_code" name="totp_code" maxlength="6" pattern="[0-9]{6}" required>
                            </div>
                            <button type="submit" name="disable_2fa" class="btn btn-outline-danger">Disable 2FA</button>
                        </form>
                    <?php else: ?>
                        <p class="text-muted">Protect your account with an extra layer of security.</p>
                        <?php if (isset($_SESSION['2fa_setup_secret'])): ?>
                            <?php 
                                $qr_url = LightweightTOTP::getQRCodeUrl('NetSentinel', $user['email'], $_SESSION['2fa_setup_secret']);
                                $qr_img = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . urlencode($qr_url);
                            ?>
                            <div class="text-center mb-3">
                                <img src="<?= $qr_img ?>" alt="2FA QR Code" class="img-fluid border p-2">
                                <p class="small text-muted mt-2">Or enter this secret manually: <code><?= $_SESSION['2fa_setup_secret'] ?></code></p>
                            </div>
                            <form method="POST" action="profile.php">
                                <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                <div class="mb-3">
                                    <label for="verify_totp_code" class="form-label">Enter 6-digit code to confirm</label>
                                    <input type="text" class="form-control text-center" id="verify_totp_code" name="totp_code" maxlength="6" pattern="[0-9]{6}" required>
                                </div>
                                <button type="submit" name="verify_2fa" class="btn btn-success w-100">Verify & Enable 2FA</button>
                            </form>
                        <?php else: ?>
                            <form method="POST" action="profile.php">
                                <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                <button type="submit" name="init_2fa" class="btn btn-success w-100">Set Up 2FA</button>
                            </form>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Danger Zone (GDPR) -->
            <div class="card border-danger shadow-sm">
                <div class="card-header bg-danger text-white"><h5 class="mb-0">Danger Zone</h5></div>
                <div class="card-body">
                    <p>Per GDPR guidelines, you have the right to erasure. Deleting your account will permanently remove your data and anonymize your activity logs.</p>
                    <form method="POST" action="profile.php" onsubmit="return confirm('Are you absolutely sure you want to delete your account? This cannot be undone.');">
                        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                        <div class="mb-3">
                            <label for="confirm_password_delete" class="form-label">Confirm Password to Delete</label>
                            <input type="password" class="form-control" id="confirm_password_delete" name="confirm_password_delete" required>
                        </div>
                        <button type="submit" name="delete_account" class="btn btn-danger w-100">Delete My Account Permanently</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>