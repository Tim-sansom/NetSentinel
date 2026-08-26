<?php
// 1. Include dependencies first
require_once 'includes/db.php';
require_once 'includes/auth.php';
require_once 'includes/audit.php';

// 2. Start session if not already started (must happen before checking $_SESSION)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// 3. Ensure user is logged in (requireLogin() handles the redirect to login.php if not)
requireLogin(); 

// 4. STRICT ADMIN CHECK: Case-insensitive (handles 'Admin', 'admin', 'ADMIN')
if (!isset($_SESSION['role']) || strtolower($_SESSION['role']) !== 'admin') {
    http_response_code(403);
    die('<div class="container mt-4"><div class="alert alert-danger">Access denied. Admin privileges required.</div></div>');
}

$message = '';
$message_type = 'success';

// Handle Form Submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $message = 'Invalid security token. Please refresh and try again.';
        $message_type = 'danger';
    } 
    // Create New User
    elseif (isset($_POST['create_user'])) {
        $username = trim($_POST['username']);
        $email = trim($_POST['email']);
        $password = $_POST['password'];
        $role = $_POST['role'] ?? 'viewer';

        if (empty($username) || empty($email) || empty($password)) {
            $message = 'All fields are required.';
            $message_type = 'danger';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $message = 'Invalid email address.';
            $message_type = 'danger';
        } elseif (strlen($password) < 8) {
            $message = 'Password must be at least 8 characters.';
            $message_type = 'danger';
        } else {
            try {
                $stmt = $pdo->prepare("SELECT user_id FROM user WHERE username = ? OR email = ?");
                $stmt->execute([$username, $email]);
                
                if ($stmt->fetch()) {
                    $message = 'Username or email already exists.';
                    $message_type = 'danger';
                } else {
                    $password_hash = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("INSERT INTO user (username, email, password_hash, role) VALUES (?, ?, ?, ?)");
                    $stmt->execute([$username, $email, $password_hash, $role]);
                    
                    $new_user_id = (int) $pdo->lastInsertId();
                    log_audit($pdo, $_SESSION['user_id'], 'USER_CREATED_BY_ADMIN', 'user', $new_user_id, ['username' => $username, 'role' => $role]);
                    
                    $message = "User '$username' created successfully.";
                }
            } catch (PDOException $e) {
                $message = 'Database error creating user.';
                $message_type = 'danger';
                error_log($e->getMessage());
            }
        }
    } 
    // Update User Role
    elseif (isset($_POST['update_role'])) {
        $target_user_id = (int) $_POST['user_id'];
        $new_role = $_POST['role'];

        if ($target_user_id === $_SESSION['user_id']) {
            $message = 'You cannot change your own role.';
            $message_type = 'danger';
        } else {
            try {
                $stmt = $pdo->prepare("UPDATE user SET role = ? WHERE user_id = ?");
                $stmt->execute([$new_role, $target_user_id]);
                log_audit($pdo, $_SESSION['user_id'], 'USER_ROLE_UPDATED', 'user', $target_user_id, ['new_role' => $new_role]);
                $message = 'User role updated successfully.';
            } catch (PDOException $e) {
                $message = 'Error updating role.';
                $message_type = 'danger';
            }
        }
    } 
    // Reset User Password
    elseif (isset($_POST['reset_password'])) {
        $target_user_id = (int) $_POST['user_id'];
        $new_password = $_POST['new_password'];

        if (strlen($new_password) < 8) {
            $message = 'Password must be at least 8 characters.';
            $message_type = 'danger';
        } else {
            try {
                $new_hash = password_hash($new_password, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("UPDATE user SET password_hash = ? WHERE user_id = ?");
                $stmt->execute([$new_hash, $target_user_id]);
                log_audit($pdo, $_SESSION['user_id'], 'USER_PASSWORD_RESET_BY_ADMIN', 'user', $target_user_id);
                $message = 'Password reset successfully.';
            } catch (PDOException $e) {
                $message = 'Error resetting password.';
                $message_type = 'danger';
            }
        }
    } 
    // Delete User (GDPR Right to Erasure)
    elseif (isset($_POST['delete_user'])) {
        $target_user_id = (int) $_POST['user_id'];

        if ($target_user_id === $_SESSION['user_id']) {
            $message = 'You cannot delete your own account from here.';
            $message_type = 'danger';
        } else {
            try {
                // Anonymize audit logs
                $pdo->prepare("UPDATE audit_log SET user_id = NULL WHERE user_id = ?")->execute([$target_user_id]);
                
                // Delete user
                $stmt = $pdo->prepare("DELETE FROM user WHERE user_id = ?");
                $stmt->execute([$target_user_id]);
                
                log_audit($pdo, $_SESSION['user_id'], 'USER_DELETED_BY_ADMIN', 'user', $target_user_id);
                $message = 'User deleted successfully.';
            } catch (PDOException $e) {
                $message = 'Error deleting user.';
                $message_type = 'danger';
            }
        }
    }
}

// Fetch all users for the table
$stmt = $pdo->query("SELECT user_id, username, email, role, totp_enabled, created_at FROM user ORDER BY created_at DESC");
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

$page_title = "Admin - User Management";
require_once 'includes/header.php';
?>

<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>User Management</h2>
        <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#createUserModal">
            <i class="bi bi-person-plus"></i> Create New User
        </button>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-<?= $message_type ?> alert-dismissible fade show" role="alert">
            <?= htmlspecialchars($message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>

    <!-- Users Table -->
    <div class="card shadow-sm">
        <div class="card-body">
            <table id="usersTable" class="table table-striped table-hover" style="width:100%">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>2FA</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $u): ?>
                        <tr>
                            <td><?= $u['user_id'] ?></td>
                            <td><?= htmlspecialchars($u['username']) ?></td>
                            <td><?= htmlspecialchars($u['email']) ?></td>
                            <td>
                                <span class="badge bg-<?= $u['role'] === 'admin' ? 'danger' : 'secondary' ?>">
                                    <?= htmlspecialchars($u['role']) ?>
                                </span>
                            </td>
                            <td>
                                <?php if ($u['totp_enabled']): ?>
                                    <span class="badge bg-success">Enabled</span>
                                <?php else: ?>
                                    <span class="badge bg-warning text-dark">Disabled</span>
                                <?php endif; ?>
                            </td>
                            <td><?= date('Y-m-d', strtotime($u['created_at'])) ?></td>
                            <td>
                                <?php if ($u['user_id'] !== $_SESSION['user_id']): ?>
                                    <button class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#editRoleModal<?= $u['user_id'] ?>">Role</button>
                                    <button class="btn btn-sm btn-outline-warning" data-bs-toggle="modal" data-bs-target="#resetPasswordModal<?= $u['user_id'] ?>">Reset PW</button>
                                    <button class="btn btn-sm btn-outline-danger" data-bs-toggle="modal" data-bs-target="#deleteUserModal<?= $u['user_id'] ?>">Delete</button>
                                <?php else: ?>
                                    <span class="text-muted small">Current user</span>
                                <?php endif; ?>
                            </td>
                        </tr>

                        <!-- Edit Role Modal -->
                        <div class="modal fade" id="editRoleModal<?= $u['user_id'] ?>" tabindex="-1">
                            <div class="modal-dialog">
                                <form method="POST" action="admin_users.php">
                                    <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                    <input type="hidden" name="user_id" value="<?= $u['user_id'] ?>">
                                    <div class="modal-content">
                                        <div class="modal-header">
                                            <h5 class="modal-title">Change Role: <?= htmlspecialchars($u['username']) ?></h5>
                                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                        </div>
                                        <div class="modal-body">
                                            <div class="mb-3">
                                                <label class="form-label">Select Role</label>
                                                <select name="role" class="form-select" required>
                                                    <option value="viewer" <?= $u['role'] === 'viewer' ? 'selected' : '' ?>>Viewer</option>
                                                    <option value="admin" <?= $u['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
                                                </select>
                                            </div>
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                            <button type="submit" name="update_role" class="btn btn-primary">Update Role</button>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>

                        <!-- Reset Password Modal -->
                        <div class="modal fade" id="resetPasswordModal<?= $u['user_id'] ?>" tabindex="-1">
                            <div class="modal-dialog">
                                <form method="POST" action="admin_users.php">
                                    <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                    <input type="hidden" name="user_id" value="<?= $u['user_id'] ?>">
                                    <div class="modal-content">
                                        <div class="modal-header">
                                            <h5 class="modal-title">Reset Password: <?= htmlspecialchars($u['username']) ?></h5>
                                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                        </div>
                                        <div class="modal-body">
                                            <div class="mb-3">
                                                <label class="form-label">New Password (min 8 chars)</label>
                                                <input type="password" name="new_password" class="form-control" minlength="8" required>
                                            </div>
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                            <button type="submit" name="reset_password" class="btn btn-warning">Reset Password</button>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>

                        <!-- Delete User Modal -->
                        <div class="modal fade" id="deleteUserModal<?= $u['user_id'] ?>" tabindex="-1">
                            <div class="modal-dialog">
                                <form method="POST" action="admin_users.php">
                                    <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                    <input type="hidden" name="user_id" value="<?= $u['user_id'] ?>">
                                    <div class="modal-content">
                                        <div class="modal-header bg-danger text-white">
                                            <h5 class="modal-title">Delete User: <?= htmlspecialchars($u['username']) ?></h5>
                                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                                        </div>
                                        <div class="modal-body">
                                            <p class="text-danger fw-bold">Warning: This action cannot be undone.</p>
                                            <p>The user's account will be permanently deleted, and their audit logs will be anonymized (GDPR Right to Erasure).</p>
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                            <button type="submit" name="delete_user" class="btn btn-danger">Delete Permanently</button>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Create User Modal -->
<div class="modal fade" id="createUserModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="POST" action="admin_users.php">
            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Create New User</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        <input type="text" name="username" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Email</label>
                        <input type="email" name="email" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password (min 8 chars)</label>
                        <input type="password" name="password" class="form-control" minlength="8" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Role</label>
                        <select name="role" class="form-select" required>
                            <option value="viewer" selected>Viewer</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" name="create_user" class="btn btn-primary">Create User</button>
                </div>
            </div>
        </form>
    </div>
</div>

<script>
$(document).ready(function() {
    $('#usersTable').DataTable({
        order: [[0, 'desc']],
        pageLength: 25
    });
});
</script>

<?php require_once 'includes/footer.php'; ?>