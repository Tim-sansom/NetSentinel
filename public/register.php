<?php
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

    // 1. Basic Validation
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
                // 3. Hash password securely (bcrypt/Argon2)
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                
                // 4. Insert new user (Default role: 'viewer')
                $stmt = $pdo->prepare("
                    INSERT INTO user (username, email, password_hash, role) 
                    VALUES (?, ?, ?, 'viewer')
                ");
                $stmt->execute([$username, $email, $password_hash]);
                
                $new_user_id = (int) $pdo->lastInsertId();

                // 5. Audit Log the registration (user_id is the new user, action by 'system' or null)
                log_audit($pdo, $new_user_id, 'USER_REGISTERED', 'user', $new_user_id, ['email' => $email]);

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
    <div class="col-md-6 col-lg-4">
        <div class="card shadow-sm">
            <div class="card-body p-4">
                <h3 class="card-title text-center mb-4">NetSentinel Register</h3>
                
                <?php if ($error): ?>
                    <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>
                
                <?php if ($success): ?>
                    <div class="alert alert-success"><?= $success ?></div>
                <?php else: ?>
                    <form method="POST" action="register.php">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required autofocus>
                        </div>
                        <div class="mb-3">
                            <label for="email" class="form-label">Email Address</label>
                            <input type="email" class="form-control" id="email" name="email" required>
                            <div class="form-text">We only collect your email for account identification. No phone number or DOB is required.</div>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required minlength="8">
                        </div>
                        <div class="mb-3">
                            <label for="confirm_password" class="form-label">Confirm Password</label>
                            <input type="password" class="form-control" id="confirm_password" name="confirm_password" required minlength="8">
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Register</button>
                    </form>
                    <div class="text-center mt-3">
                        <small>Already have an account? <a href="login.php">Log in here</a>.</small>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>