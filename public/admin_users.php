<?php
/**
 * NetSentinel User Management Page
 * Admin-only user CRUD operations, role assignment, 
 * and GDPR-compliant Right to Erasure.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/audit.php';

if (session_status() === PHP_SESSION_NONE) { 
    session_start(); 
}
requireLogin();

if (!isset($_SESSION['role']) || strtolower($_SESSION['role']) !== 'admin') {
    http_response_code(403);
    die('<div class="container mt-4"><div class="alert alert-danger">Access denied. Admin privileges required.</div></div>');
}

$message = '';
$message_type = 'success';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $message = 'Invalid security token. Please refresh and try again.';
        $message_type = 'danger';
    } 
    // Create User
    elseif (isset($_POST['create_user'])) {
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $role = $_POST['role'] ?? 'viewer';

        if (empty($username) || empty($email) || empty($password)) {
            $message = 'Username, email, and password are required.';
            $message_type = 'danger';
        } else {
            try {
                $checkStmt = $pdo->prepare("SELECT user_id FROM user WHERE username = ? OR email = ?");
                $checkStmt->execute([$username, $email]);
                if ($checkStmt->fetch()) {
                    $message = 'Username or email already exists.';
                    $message_type = 'danger';
                } else {
                    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("INSERT INTO user (username, email, password_hash, role) VALUES (?, ?, ?, ?)");
                    $stmt->execute([$username, $email, $hashed_password, $role]);
                    
                    log_audit($pdo, $_SESSION['user_id'], 'USER_CREATED', 'user', $pdo->lastInsertId());
                    $message = 'User created successfully.';
                }
            } catch (PDOException $e) {
                $message = 'Database error: ' . htmlspecialchars($e->getMessage());
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
                // GDPR COMPLIANCE: Anonymize the audit trail (set user_id to NULL) BEFORE deleting the user.
                $pdo->prepare("UPDATE audit_log SET user_id = NULL WHERE user_id = ?")->execute([$target_user_id]);
                
                // Delete the user record
                $stmt = $pdo->prepare("DELETE FROM user WHERE user_id = ?");
                $stmt->execute([$target_user_id]);
                
                log_audit($pdo, $_SESSION['user_id'], 'USER_DELETED_BY_ADMIN', 'user', $target_user_id);
                $message = 'User deleted successfully.';
            } catch (PDOException $e) {
                $message = 'Error deleting user: ' . htmlspecialchars($e->getMessage());
                $message_type = 'danger';
            }
        }
    }
}

// Fetch all users for the table
$stmt = $pdo->query("SELECT user_id, username, email, role, totp_enabled, created_at FROM user ORDER BY created_at DESC");
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

$page_title = "Admin - User Management";
require_once __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-people-fill"></i> User Management</h2>
        <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addUserModal">
            <i class="bi bi-person-plus"></i> Add New User
        </button>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-<?= htmlspecialchars($message_type) ?> alert-dismissible fade show" role="alert">
            <?= htmlspecialchars($message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>

    <!-- Users Table -->
    <div class="card shadow-sm">
        <div class="card-header bg-white">
            <h5 class="mb-0">Registered Users</h5>
        </div>
        <div class="card-body">
            <?php if (empty($users)): ?>
                <div class="text-center py-5">
                    <i class="bi bi-people display-4 text-muted"></i>
                    <p class="text-muted mt-3">No users found. Click "Add New User" to get started.</p>
                </div>
            <?php else: ?>
                <div class="table-responsive">
                    <table id="usersTable" class="table table-hover align-middle mb-0">
                        <thead class="table-light">
                            <tr>
                                <th>Username</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>2FA Status</th>
                                <th>Created At</th>
                                <th class="text-end">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($users as $user): ?>
                            <tr>
                                <td class="fw-bold"><?= htmlspecialchars($user['username']) ?></td>
                                <td><?= htmlspecialchars($user['email']) ?></td>
                                <td>
                                    <span class="badge <?= strtolower($user['role']) === 'admin' ? 'bg-danger' : 'bg-secondary' ?>">
                                        <?= ucfirst(htmlspecialchars($user['role'])) ?>
                                    </span>
                                </td>
                                <td>
                                    <?php if ($user['totp_enabled']): ?>
                                        <span class="badge bg-success"><i class="bi bi-shield-check"></i> Enabled</span>
                                    <?php else: ?>
                                        <span class="badge bg-warning text-dark"><i class="bi bi-shield-x"></i> Disabled</span>
                                    <?php endif; ?>
                                </td>
                                <td><?= date('d M Y', strtotime($user['created_at'])) ?></td>
                                <td class="text-end">
                                    <?php if ($user['user_id'] !== $_SESSION['user_id']): ?>
                                        <form method="POST" action="admin_users.php" onsubmit="return confirm('Are you sure you want to delete this user? This action cannot be undone and will anonymize their audit logs.');" style="display: inline;">
                                            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                            <input type="hidden" name="user_id" value="<?= $user['user_id'] ?>">
                                            <input type="hidden" name="delete_user" value="1">
                                            <button type="submit" class="btn btn-sm btn-outline-danger">
                                                <i class="bi bi-trash"></i> Delete
                                            </button>
                                        </form>
                                    <?php else: ?>
                                        <span class="text-muted small fst-italic">Current User</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Add User Modal -->
<div class="modal fade" id="addUserModal" tabindex="-1" aria-labelledby="addUserModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <form method="POST" action="admin_users.php">
                <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                <input type="hidden" name="create_user" value="1">
                <div class="modal-header">
                    <h5 class="modal-title" id="addUserModalLabel">Add New User</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="email" class="form-label">Email <span class="text-danger">*</span></label>
                        <input type="email" class="form-control" id="email" name="email" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password <span class="text-danger">*</span></label>
                        <input type="password" class="form-control" id="password" name="password" required minlength="8">
                        <div class="form-text">Minimum 8 characters.</div>
                    </div>
                    <div class="mb-3">
                        <label for="role" class="form-label">Role</label>
                        <select class="form-select" id="role" name="role">
                            <option value="viewer">Viewer</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create User</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    $('#usersTable').DataTable({
        order: [[4, 'desc']], // Sort by Created At descending
        pageLength: 10,
        language: {
            search: "Filter users:"
        },
        columnDefs: [
            { targets: [5], orderable: false } // Disable sorting on Actions column
        ]
    });
});
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>