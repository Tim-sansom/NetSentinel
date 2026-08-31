<?php
/**
 * NetSentinel Password Reset Request
 */
require_once 'includes/db.php';
require_once 'vendor/autoload.php'; // Load Composer autoloader for PHPMailer
require_once 'includes/smtp_config.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'request_reset') {
    $email = trim($_POST['email'] ?? '');
    
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    } else {
        try {
            // Check if email exists
            $stmt = $pdo->prepare("SELECT user_id, username FROM user WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user) {
                // Generate secure reset token
                $reset_token = bin2hex(random_bytes(32));
                $expires = date('Y-m-d H:i:s', strtotime('+1 hour'));
                
                // Store token in database
                $stmt = $pdo->prepare("
                    INSERT INTO password_resets (user_id, token, expires_at) 
                    VALUES (?, ?, ?)
                    ON DUPLICATE KEY UPDATE token = ?, expires_at = ?
                ");
                $stmt->execute([$user['user_id'], $reset_token, $expires, $reset_token, $expires]);
                
                // Send email using PHPMailer
                $mail = new PHPMailer(true);
                try {
                    // Server settings
                    $mail->isSMTP();
                    $mail->Host       = SMTP_HOST;
                    $mail->SMTPAuth   = true;
                    $mail->Username   = SMTP_USERNAME;
                    $mail->Password   = SMTP_PASSWORD;
                    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS; // Matches port 587
                    $mail->Port       = SMTP_PORT;
                    
                    // Recipients
                    $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
                    $mail->addAddress($email, $user['username']);
                    
                    // Content
                    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
                    $host = $_SERVER['HTTP_HOST'];
                    $reset_link = "{$protocol}://{$host}/reset_password.php?token=" . $reset_token;
                    
                    $mail->isHTML(true);
                    $mail->Subject = 'NetSentinel Password Reset Request';
                    $mail->Body    = "
                        <h2>Password Reset Request</h2>
                        <p>Hello {$user['username']},</p>
                        <p>You have requested to reset your password for your NetSentinel account.</p>
                        <p>Click the button below to set a new password. This link will expire in 1 hour.</p>
                        <p><a href='{$reset_link}' style='background-color: #0d6efd; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 10px;'>Reset Password</a></p>
                        <p style='margin-top: 20px; color: #6c757d; font-size: 14px;'>If you did not request this, please ignore this email.</p>
                    ";
                    $mail->AltBody = "Hello {$user['username']},\n\nYou have requested to reset your password. Click this link to set a new password (expires in 1 hour):\n{$reset_link}\n\nIf you did not request this, please ignore this email.";
                    
                    $mail->send();
                    $success = "A password reset link has been sent to your email address. Please check your inbox (and spam folder).";
                } catch (Exception $e) {
                    error_log("PHPMailer Error: {$mail->ErrorInfo}");
                    $error = "Failed to send reset email. Please check server logs or contact the administrator.";
                }
            } else {
                // Security best practice: Don't reveal if the email exists or not
                $success = "If an account exists with that email address, a password reset link has been sent.";
            }
        } catch (PDOException $e) {
            error_log("Password reset request DB error: " . $e->getMessage());
            $error = 'An error occurred. Please try again later.';
        }
    }
}

$page_title = "Forgot Password";
require_once 'includes/header.php';
?>

<div class="row justify-content-center mt-5">
    <div class="col-md-5 col-lg-4">
        <div class="card shadow-sm">
            <div class="card-header bg-primary text-white text-center">
                <h4 class="mb-0"><i class="bi bi-key"></i> Password Reset</h4>
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
                
                <p class="text-muted mb-4">Enter your email address and we'll send you instructions to reset your password.</p>
                
                <form method="POST" action="forgot_password.php">
                    <input type="hidden" name="action" value="request_reset">
                    
                    <div class="mb-3">
                        <label for="email" class="form-label">Email Address</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-envelope"></i></span>
                            <input type="email" class="form-control" id="email" name="email" 
                                   value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" required autofocus autocomplete="email">
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary w-100 py-2">
                        <i class="bi bi-send"></i> Send Reset Instructions
                    </button>
                </form>
            </div>
            <div class="card-footer text-center">
                <a href="login.php" class="small text-muted">
                    <i class="bi bi-arrow-left"></i> Back to Login
                </a>
            </div>
        </div>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>