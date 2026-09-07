<?php
/**
 * NetSentinel User Registration & Auto-Provisioning Page
 * ================================================================================
 * 
 * PURPOSE:
 * Handles new user registration with strict input validation, GDPR-compliant 
 * data minimization, and automatic multi-tenant workspace provisioning.
 * 
 * ACADEMIC SIGNIFICANCE:
 * This script demonstrates a secure, atomic auto-provisioning workflow for SaaS 
 * applications. Instead of requiring manual administrator intervention, it creates 
 * a new tenant (device_group) and an admin user in a single, atomic database transaction.
 * 
 * SECURITY & COMPLIANCE BOUNDARIES:
 * - SR3 (Input Validation): Strict server-side sanitization and validation.
 * - SR4 (Audit & Compliance): Logs the provisioning event for tamper-evident trails.
 * - GDPR Data Minimization: Collects ONLY essential fields (Company, Username, Email, Password).
 * - Data Integrity: Uses PDO transactions to prevent orphaned records (e.g., a user 
 *   created without a group, or a group created without an owner) if a query fails.
 * 
 * @author Tim Sansom
 * @version 1.0
 * @date 2026
 */

require_once 'includes/db.php';
require_once 'includes/audit.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Redirect authenticated users to prevent redundant registration attempts
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 1. Sanitize and capture input (GDPR Data Minimization)
    $company_name = trim($_POST['company_name'] ?? '');
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // 2. SR3: Strict server-side validation
    if (empty($company_name) || empty($username) || empty($email) || empty($password) || empty($confirm_password)) {
        $error = 'All fields are required.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    } elseif ($password !== $confirm_password) {
        $error = 'Passwords do not match.';
    } elseif (strlen($password) < 8) {
        $error = 'Password must be at least 8 characters long.';
    } else {
        try {
            // 3. Check for existing credentials to prevent duplication
            $stmt = $pdo->prepare("SELECT user_id FROM user WHERE username = ? OR email = ?");
            $stmt->execute([$username, $email]);
            
            if ($stmt->fetch()) {
                $error = 'Username or email is already registered.';
            } else {
                // 4. SECURITY: Start Atomic Transaction for Auto-Provisioning
                // Ensures all-or-nothing execution. Prevents orphaned records if a query fails.
                $pdo->beginTransaction();

                // 5. Create a new isolated Device Group (Tenant) for this company
                // owner_id is temporarily NULL, updated in step 8 after user creation.
                $stmt_group = $pdo->prepare("
                    INSERT INTO device_group (name, description, owner_id) 
                    VALUES (?, 'Auto-provisioned tenant', NULL)
                ");
                $stmt_group->execute([$company_name]);
                $new_group_id = (int) $pdo->lastInsertId();

                // 6. Secure Password Hashing
                // PASSWORD_DEFAULT uses bcrypt (or Argon2 in newer PHP), ensuring 
                // credentials are never stored in plaintext, even if the DB is compromised.
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                
                // 7. Create the User and assign them as 'admin' of the new group
                $stmt_user = $pdo->prepare("
                    INSERT INTO user (username, email, password_hash, role, group_id)
                    VALUES (?, ?, ?, 'admin', ?)
                ");
                $stmt_user->execute([$username, $email, $password_hash, $new_group_id]);
                $new_user_id = (int) $pdo->lastInsertId();

                // 8. Resolve Circular Dependency: Link the group back to the new owner
                $stmt_update_group = $pdo->prepare("
                    UPDATE device_group SET owner_id = ? WHERE group_id = ?
                ");
                $stmt_update_group->execute([$new_user_id, $new_group_id]);

                // 9. Commit the transaction (makes all changes permanent)
                $pdo->commit();
                
                // 10. SR4: Audit Log the registration and auto-provisioning event
                if (function_exists('log_audit')) {
                    log_audit(
                        $pdo, 
                        $new_user_id, 
                        'TENANT_AUTO_PROVISIONED', 
                        'device_group', 
                        $new_group_id, 
                        json_encode(['company' => $company_name, 'email' => $email])
                    );
                }
                
                $success = 'Account and company workspace created successfully! You are the Admin. Please <a href="login.php">log in</a>.';
            }
        } catch (PDOException $e) {
            // Rollback transaction if ANY step fails to maintain database integrity
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            $error = 'Registration failed. The username or email may already be in use, or a database error occurred.';
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

                <!-- Error Alert (SR3: Output escaping prevents XSS) -->
                <?php if ($error): ?>
                    <div class="alert alert-danger alert-dismissible fade show" role="alert">
                        <i class="bi bi-exclamation-triangle"></i> <?= htmlspecialchars($error) ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>
                
                <!-- Registration Form -->
                <form method="POST" action="register.php">
                    <div class="mb-3">
                        <label for="company_name" class="form-label">Company / Organization Name</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-building"></i></span>
                            <!-- SR3: htmlspecialchars prevents XSS on form repopulation -->
                            <input type="text" class="form-control" id="company_name" name="company_name" 
                                   value="<?= htmlspecialchars($_POST['company_name'] ?? '') ?>" required autofocus>
                        </div>
                        <div class="form-text">This will be the name of your isolated workspace.</div>
                    </div>

                    <div class="mb-3">
                        <label for="username" class="form-label">Admin Username</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="bi bi-person"></i></span>
                            <input type="text" class="form-control" id="username" name="username" 
                                   value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" required>
                        </div>
                    </div>

                    <div class="mb-3">
                        <label for="email" class="form-label">Admin Email Address</label>
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
                    
                    <button type="submit" class="btn btn-primary w-100 py-2" data-bs-toggle="tooltip" data-bs-title="Click to create your account and workspace">
                        <i class="bi bi-person-plus"></i> Create Admin Account
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