<?php
/**
 * NetSentinel Reset Password (Token Verification)
 * SR2: Secure password reset with token validation and expiration
 */
require_once __DIR__ . '/includes/db.php';

$success = '';
$error = '';
$token = $_GET['token'] ?? '';
$valid_token = false;
$user_data = null;

// Verify token
if (!empty($token)) {
    try {
        $stmt = $pdo->prepare("
            SELECT pr.user_id, pr.expires_at, u.username, u.email 
            FROM password_resets pr
            JOIN `user` u ON pr.user_id = u.user_id
            WHERE pr.token = ? AND pr.expires_at > NOW()
        ");
        $stmt->execute([$token]);
        $reset_data = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($reset_data) {
            $valid_token = true;
            $user_data = $reset_data;
        } else {
            $error = 'Invalid or expired reset token. Please request a new password reset.';
        }
    } catch (PDOException $e) {
        error_log("Token verification error: " . $e->getMessage());
        $error = 'An error occurred. Please try again.';
    }
}

// Handle password update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $valid_token) {
    $new_password = $_POST['new_password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    
    if (empty($new_password) || empty($confirm_password)) {
        $error = 'Please fill in all fields.';
    } elseif ($new_password !== $confirm_password) {
        $error = 'Passwords do not match.';
    } elseif (strlen($new_password) < 8) {
        $error = 'Password must be at least 8 characters long.';
    } else {
        try {
            // Hash new password using bcrypt (PASSWORD_DEFAULT)
            $password_hash = password_hash($new_password, PASSWORD_DEFAULT);
            
            // Update user password
            $stmt = $pdo->prepare("UPDATE `user` SET password_hash = ? WHERE user_id = ?");
            $stmt->execute([$password_hash, $user_data['user_id']]);
            
            // Delete used token (prevent reuse)
            $stmt = $pdo->prepare("DELETE FROM password_resets WHERE user_id = ?");
            $stmt->execute([$user_data['user_id']]);
            
            $success = "Password successfully updated! You can now <a href='login.php'>log in</a> with your new password.";
            $valid_token = false;
            
        } catch (PDOException $e) {
            error_log("Password update error: " . $e->getMessage());
            $error = 'An error occurred while updating your password.';
        }
    }
}

$page_title = "Reset Password";
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center mt-5">
    <div class="col-md-5 col-lg-4">
        <div class="card shadow-sm">
            <div class="card-header bg-primary text-white text-center">
                <h4 class="mb-0"><i class="bi bi-shield-lock"></i> Set New Password</h4>
            </div>
            <div class="card-body p-4">
                
                <?php if ($success): ?>
                    <div class="alert alert-success" role="alert">
                        <i class="bi bi-check-circle"></i> <?= $success ?>
                    </div>
                <?php endif; ?>

                <?php if ($error): ?>
                    <div class="alert alert-danger" role="alert">
                        <i class="bi bi-exclamation-triangle"></i> <?= htmlspecialchars($error) ?>
                    </div>
                <?php endif; ?>
                
                <?php if ($valid_token): ?>
                    <p class="text-muted mb-4">
                        Resetting password for: <strong><?= htmlspecialchars($user_data['email']) ?></strong>
                    </p>
                    
                    <form method="POST" action="reset_password.php?token=<?= htmlspecialchars($token) ?>">
                        <div class="mb-3">
                            <label for="new_password" class="form-label">New Password</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="bi bi-lock"></i></span>
                                <input type="password" class="form-control" id="new_password" name="new_password" 
                                       required autofocus autocomplete="new-password" minlength="8">
                            </div>
                            <div class="form-text">Minimum 8 characters</div>
                        </div>
                        
                        <div class="mb-4">
                            <label for="confirm_password" class="form-label">Confirm New Password</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="bi bi-lock-fill"></i></span>
                                <input type="password" class="form-control" id="confirm_password" name="confirm_password" 
                                       required autocomplete="new-password">
                            </div>
                        </div>
                        
                        <button type="submit" class="btn btn-primary w-100 py-2">
                            <i class="bi bi-check-circle"></i> Update Password
                        </button>
                    </form>
                <?php else: ?>
                    <?php if (!$error): ?>
                        <div class="alert alert-warning">
                            <i class="bi bi-exclamation-circle"></i> No valid reset token provided.
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
            <div class="card-footer text-center">
                <a href="login.php" class="small text-muted">
                    <i class="bi bi-arrow-left"></i> Back to Login
                </a>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>