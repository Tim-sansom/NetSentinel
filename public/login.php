<?php
/**
 * NetSentinel Login Page
 * Handles user authentication, session creation, and secure redirection.
 * 
 * SECURITY NOTE: Implements environment-aware error reporting to prevent 
 * information leakage in production (OWASP A05: Security Misconfiguration).
 */

// 1. Environment-aware error reporting (OWASP A05)
// Only show errors if we are in the development environment (Docker)
if (getenv('NETSENTINEL_ENV') === 'development') {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    // In production, hide errors from users but log them to a file
    error_reporting(0);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/includes/db.php';

// If already logged in, redirect to dashboard
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$timeout = isset($_GET['timeout']) && $_GET['timeout'] == 1;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $login_identifier = trim($_POST['login_identifier'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($login_identifier) || empty($password)) {
        $error = 'Please enter both your username/email and password.';
    } else {
        try {
            // SECURITY: Prepared statement prevents SQL injection (SR3)
            $stmt = $pdo->prepare("SELECT user_id, username, email, password_hash, role, group_id FROM user WHERE username = ? OR email = ?");
            $stmt->execute([$login_identifier, $login_identifier]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            // SECURITY: Secure password verification using bcrypt/argon2
            if ($user && password_verify($password, $user['password_hash'])) {
                // SECURITY: Prevent session fixation attacks by regenerating session ID
                session_regenerate_id(true);
                
                $_SESSION['user_id'] = $user['user_id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'] ?? 'viewer';
                $_SESSION['group_id'] = $user['group_id'] ?? null;
                $_SESSION['last_activity'] = time();
                
                header('Location: dashboard.php');
                exit;
            } else {
                // SECURITY: Generic error message to prevent account enumeration
                $error = 'Invalid credentials.';
            }
        } catch (PDOException $e) {
            // SECURITY: Log the actual error internally, but show a generic message to the user
            error_log("Login DB Error: " . $e->getMessage());
            $error = 'Database error. Please try again later.';
        }
    }
}

$page_title = "Login";
require_once __DIR__ . '/includes/header.php';
?>

<div class="row justify-content-center mt-5">
    <div class="col-md-5 col-lg-4">
        <div class="card shadow-sm">
            <div class="card-header bg-primary text-white text-center">
                <h4 class="mb-0"><i class="bi bi-shield-lock"></i> NetSentinel Login</h4>
            </div>
            <div class="card-body p-4">
                
                <?php if ($timeout): ?>
                    <div class="alert alert-warning alert-dismissible fade show" role="alert">
                        <i class="bi bi-clock-history"></i> <strong>Session Expired:</strong> You have been logged out due to inactivity.
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>

                <?php if ($error): ?>
                    <div class="alert alert-danger alert-dismissible fade show" role="alert">
                        <i class="bi bi-exclamation-triangle"></i> <?= htmlspecialchars($error) ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>
                
                <form method="POST" action="login.php">
                    <div class="mb-3">
                        <label for="login_identifier" class="form-label">Username or Email</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-person"></i></span>
                            <input type="text" class="form-control" id="login_identifier" name="login_identifier" 
                                   value="<?= htmlspecialchars($_POST['login_identifier'] ?? '') ?>" 
                                   required autofocus autocomplete="username">
                        </div>
                    </div>
                    
                    <div class="mb-4">
                        <label for="password" class="form-label">Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-lock"></i></span>
                            <input type="password" class="form-control" id="password" name="password" 
                                   required autocomplete="current-password">
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary w-100 py-2" 
                            data-bs-toggle="tooltip" 
                            data-bs-placement="top" 
                            data-bs-title="Click to sign in to your account">
                        <i class="bi bi-box-arrow-in-right"></i> Sign In
                    </button>
                </form>
            </div>
            <div class="card-footer text-center">
                <a href="forgot_password.php" class="small text-muted">Forgot Password?</a>
            </div>
        </div>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    });
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>