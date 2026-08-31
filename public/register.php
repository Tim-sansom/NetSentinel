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
                
                // 4. GDPR Data Minimization: Only store essential data. Default role is 'viewer'.
                $stmt = $pdo->prepare("
                    INSERT INTO user (username, email, password_hash, role)
                    VALUES (?, ?, ?, 'viewer')
                ");
                $stmt->execute([$username, $email, $password_hash]);
                
                $new_user_id = (int) $pdo->lastInsertId();
                
                // 5. Audit Log the registration
                if (function_exists('log_audit')) {
                    log_audit($pdo, $new_user_id, 'USER_REGISTERED', 'user', $new_user_id, json_encode(['email' => $email]));
                }
                
                $success = 'Registration successful! You can now <a href="login.php">log in</a>.';
            }
        } catch (PDOException $e) {
            $error = 'Database error. Please try again later.';
            error_log("Registration DB error: " . $e->getMessage());
        }
    }
}

$page_title = "Register";
require_once 'includes/header.php';
?>

<div class="row justify-content-center mt-5">
    <div class="col-md-6 col-lg-5">
        <div class="card shadow-sm">
            <div class="card-header bg-primary text-white text-center">
                <h4 class="mb-0"><i class="bi bi-person-plus"></i> NetSentinel Register</h4>
            </div>
            <div class="card-body p-4">
                
                <!-- Success Alert -->
                <?php if ($success): ?>
                    <div class="alert alert-success alert-dismissible fade show" role="alert">
                        <i class="bi bi-check-circle"></i> <?= $success ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>

                <!-- Error Alert -->
                <?php if ($error): ?>
                    <div class="alert alert-danger alert-dismissible fade show" role="alert">
                        <i class="bi bi-exclamation-triangle"></i> <?= htmlspecialchars($error) ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>
                
                <!-- Complete, working form -->
                <form method="POST" action="register.php">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-person"></i></span>
                            <input type="text" class="form-control" id="username" name="username" 
                                   value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" required autofocus>
                        </div>
                    </div>

                    <div class="mb-3">
                        <label for="email" class="form-label">Email Address</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-envelope"></i></span>
                            <input type="email" class="form-control" id="email" name="email" 
                                   value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" required>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-lock"></i></span>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <div class="form-text">Must be at least 8 characters long.</div>
                    </div>

                    <div class="mb-4">
                        <label for="confirm_password" class="form-label">Confirm Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-lock-fill"></i></span>
                            <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                        </div>
                    </div>
                    
                    <!-- Added tooltip attributes here -->
                    <button type="submit" class="btn btn-primary w-100 py-2" data-bs-toggle="tooltip" data-bs-title="Click to create your account">
                        <i class="bi bi-person-plus"></i> Register
                    </button>
                </form>
            </div>
            <div class="card-footer text-center text-muted small">
                Already have an account? <a href="login.php">Sign in here</a>
            </div>
        </div>
    </div>
</div>

<!-- Initialize Bootstrap Tooltips -->
<script>
    document.addEventListener('DOMContentLoaded', function() {
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    });
</script>

<?php require_once 'includes/footer.php'; ?>