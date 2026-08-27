<?php
// 1. Enable errors temporarily for debugging (REMOVE THESE 3 LINES FOR PRODUCTION/SUBMISSION)
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

// 2. SECURITY: Start session immediately
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/includes/db.php';

// If already logged in, redirect to dashboard to prevent redundant logins
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$timeout = isset($_GET['timeout']) && $_GET['timeout'] == 1;

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
                session_regenerate_id(true);
                
                $_SESSION['user_id'] = $user['user_id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'] ?? 'viewer';
                $_SESSION['last_activity'] = time(); // Initialize timeout tracker
                
                header('Location: dashboard.php');
                exit;
            } else {
                // Generic error message to prevent User Enumeration
                $error = 'Invalid credentials.';
            }
        } catch (PDOException $e) {
            $error = 'Database error. Please try again later.';
            error_log("Login DB Error: " . $e->getMessage());
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
                
                <!-- Session Timeout Alert -->
                <?php if ($timeout): ?>
                    <div class="alert alert-warning alert-dismissible fade show" role="alert">
                        <i class="bi bi-clock-history"></i> <strong>Session Expired:</strong> You have been logged out due to inactivity. Please log in again.
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>

                <!-- Standard Error Alert -->
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
                                   value="<?= htmlspecialchars($_POST['login_identifier'] ?? '') ?>" required autofocus>
                        </div>
                    </div>
                    
                    <div class="mb-4">
                        <label for="password" class="form-label">Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-lock"></i></span>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary w-100 py-2">
                        <i class="bi bi-box-arrow-in-right"></i> Sign In
                    </button>
                </form>
            </div>
            <div class="card-footer text-center text-muted small">
                Default credentials: <strong>admin</strong> / <strong>NetSentinel2026!</strong>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>