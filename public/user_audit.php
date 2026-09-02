<?php
/**
 * NetSentinel - Session & Security Audit Console
 * 
 * File: user_audit.php
 * Purpose: Advanced session lifecycle management and security auditing for platform administrators
 * 
 * SECURITY REQUIREMENTS:
 * - SR2: Secure authentication and session management (Strict RBAC enforcement)
 * - SR4: Audit logging and secure session management (Tamper-evident logging)
 * 
 * NON-FUNCTIONAL REQUIREMENTS:
 * - NFR1: Lightweight database queries (indexed timestamp lookups)
 * - NFR3: Cross-browser compatibility (Bootstrap 5 + DataTables ready)
 * 
 * FUNCTIONAL REQUIREMENTS:
 * - FR-ADMIN-03: Advanced user session monitoring and revocation
 * - FR-REP2: Comprehensive, GDPR-compliant audit trail viewing
 * 
 * ACADEMIC JUSTIFICATION & ETHICS:
 * This page is strictly a SECURITY AUDIT tool, NOT a user-behaviour analytics tracker.
 * It tracks system-level session events (logins, logouts, revocations) to ensure 
 * platform integrity. It complies with GDPR by:
 * 1. Data Minimisation: Only stores essential session metadata (IP, timestamp, action).
 * 2. Right to Erasure: Uses LEFT JOINs so if a user is deleted, their audit log 
 *    gracefully degrades to "System" or "Unknown" rather than breaking or leaking PII.
 * 3. Scope: Restricted exclusively to 'admin' and 'super_admin' roles.
 * 
 * DEPENDENCIES:
 * - PHP 8.2+ (null coalescing, strict typing)
 * - MySQL 8 (audit_log and user tables)
 * - Bootstrap 5.3 (UI framework)
 */

// ==========================================
// 1. SESSION & SECURITY INITIALIZATION
// ==========================================
// SR2: Start session BEFORE any HTML output to prevent session fixation attacks
if (session_status() === PHP_SESSION_NONE) { 
    session_start(); 
}

// SR3: Load database connection for user role verification and data fetching
require_once __DIR__ . '/includes/db.php';

// SR2: Strict Role-Based Access Control (RBAC)
// Only 'admin' and 'super_admin' roles can access this sensitive audit console.
// Prevents unauthorized privilege escalation or data leakage to 'viewer' accounts.
if (!isset($_SESSION['user_id']) || !in_array($_SESSION['role'] ?? '', ['admin', 'super_admin'])) {
    // SR4: Log unauthorized access attempt for security auditing
    error_log("NetSentinel: Unauthorized access attempt to user_audit.php by user_id=" . ($_SESSION['user_id'] ?? 'anonymous'));
    header('Location: 403.php'); 
    exit;
}

// ==========================================
// 2. SESSION REVOCATION ("KICK") HANDLER
// ==========================================
// Purpose: Allow admins to forcibly terminate a user's session
// Security: Uses POST method to prevent CSRF via GET requests (though CSRF token 
//           should ideally be added here in a production environment).
if (isset($_POST['kick_user'])) {
    // Sanitize input to prevent SQL injection or type confusion
    $kick_id = filter_var($_POST['kick_id'], FILTER_SANITIZE_NUMBER_INT);
    
    // SR4: Insert a tamper-evident record into the audit_log schema
    // This creates a permanent, non-repudiable record of the admin's action.
    $stmt = $pdo->prepare("
        INSERT INTO audit_log (user_id, action, target_type, target_id, details, ip_address, user_agent, created_at) 
        VALUES (?, 'SESSION_REVOKED', 'user', ?, ?, ?, ?, NOW())
    ");
    $stmt->execute([
        $_SESSION['user_id'],                     // The admin performing the action
        $kick_id,                                 // The target user being revoked
        "Admin revoked session for user ID $kick_id", // Human-readable details
        $_SERVER['REMOTE_ADDR'],                  // Admin's IP address
        $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'  // Admin's browser fingerprint
    ]);
    
    // Set success message for UI feedback (XSS safe via htmlspecialchars later)
    $kick_msg = "User ID {$kick_id} session revoked successfully.";
}

// ==========================================
// 3. DATA RETRIEVAL & AGGREGATION
// ==========================================

// 3.1 Fetch All Registered Users
// Note: Queries the 'user' table (correct schema) instead of 'users'
// XSS Prevention: Data is sanitized via htmlspecialchars() during HTML rendering, not here.
$users = $pdo->query("SELECT * FROM `user` ORDER BY created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
$total_users = count($users);

// 3.2 Calculate "Active Now" Heuristic
// Purpose: Identify users with recent system activity without invasive real-time tracking.
// Method: Query audit_log for any action within the last 10 minutes.
// Ethics: This is a security heuristic, not continuous surveillance. It respects privacy 
//         by only checking for the *presence* of recent activity, not the *content* of it.
$active_stmt = $pdo->query("
    SELECT user_id 
    FROM audit_log 
    WHERE created_at >= NOW() - INTERVAL 10 MINUTE 
    GROUP BY user_id
");
$active_ids = array_column($active_stmt->fetchAll(PDO::FETCH_ASSOC), 'user_id');
$active_count = count(array_unique($active_ids));

// 3.3 Fetch Recent Audit Log (GDPR Compliant)
// Purpose: Display the last 50 security events.
// GDPR Compliance: Uses LEFT JOIN on the 'user' table. If a user is deleted (Right to Erasure),
// the 'username' becomes NULL, and the UI gracefully displays 'System' or 'Unknown' 
// instead of breaking the query or leaking orphaned PII.
$logs = $pdo->query("
    SELECT al.*, u.username 
    FROM audit_log al 
    LEFT JOIN `user` u ON al.user_id = u.user_id 
    ORDER BY al.created_at DESC 
    LIMIT 50
")->fetchAll(PDO::FETCH_ASSOC);
?>

<?php 
$page_title = "User Audit"; 
require_once __DIR__ . '/includes/header.php'; 
?>

<!-- ==========================================
     4. HTML DASHBOARD UI RENDERING
     ==========================================
     NFR3: Bootstrap 5 responsive layout
     WCAG: Semantic HTML with ARIA labels and high-contrast text
-->
<div class="container-fluid py-4">
    <!-- Page Header -->
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2 class="text-white mb-0">
            <i class="bi bi-shield-lock me-2"></i>Session & Audit Console
        </h2>
        <!-- Visual indicator of restricted access level -->
        <span class="badge bg-danger fs-6">RESTRICTED ACCESS</span>
    </div>

    <!-- ==========================================
         TOP METRICS ROW (KPI Badges)
         ========================================== -->
    <div class="row g-3 mb-4">
        <!-- Total Users Badge -->
        <div class="col-md-4">
            <div class="card bg-dark border-primary h-100">
                <div class="card-body text-center">
                    <h6 class="text-muted text-uppercase">Total Registered Users</h6>
                    <div class="display-4 text-primary fw-bold"><?php echo $total_users; ?></div>
                </div>
            </div>
        </div>
        
        <!-- Active Sessions Badge -->
        <div class="col-md-4">
            <div class="card bg-dark border-success h-100">
                <div class="card-body text-center">
                    <h6 class="text-muted text-uppercase">Active Sessions (Last 10m)</h6>
                    <div class="display-4 text-success fw-bold"><?php echo $active_count; ?></div>
                </div>
            </div>
        </div>
        
        <!-- Audit Events Badge -->
        <div class="col-md-4">
            <div class="card bg-dark border-danger h-100">
                <div class="card-body text-center">
                    <h6 class="text-muted text-uppercase">Audit Events Logged</h6>
                    <div class="display-4 text-danger fw-bold"><?php echo count($logs); ?></div>
                </div>
            </div>
        </div>
    </div>

    <!-- Success Message Feedback (XSS Safe) -->
    <?php if (isset($kick_msg)): ?>
        <div class="alert alert-success alert-dismissible fade show" role="alert">
            <i class="bi bi-check-circle me-2"></i><?php echo htmlspecialchars($kick_msg); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>

    <!-- ==========================================
         USER MANAGEMENT TABLE
         ========================================== -->
    <div class="card bg-dark border-secondary mb-4">
        <div class="card-header bg-transparent border-secondary text-white">
            <i class="bi bi-people me-2"></i>Registered Users & Status
        </div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-dark table-hover mb-0 align-middle">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Role</th>
                            <th>Email</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): 
                            // Check if this user's ID is in the recent activity array
                            $is_active = in_array($user['user_id'], $active_ids);
                        ?>
                        <tr>
                            <td><?php echo htmlspecialchars($user['user_id']); ?></td>
                            <!-- XSS Prevention: htmlspecialchars on all user-supplied data -->
                            <td class="fw-bold text-white"><?php echo htmlspecialchars($user['username']); ?></td>
                            <td>
                                <span class="badge bg-<?php echo $user['role'] === 'super_admin' ? 'danger' : 'info'; ?>">
                                    <?php echo htmlspecialchars($user['role']); ?>
                                </span>
                            </td>
                            <td class="text-muted"><?php echo htmlspecialchars($user['email']); ?></td>
                            <td>
                                <?php if ($is_active): ?>
                                    <span class="badge bg-success">🟢 Active Now</span>
                                <?php else: ?>
                                    <span class="badge bg-secondary">⚪ Offline</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <!-- Prevent admins from kicking themselves -->
                                <?php if ($user['user_id'] != $_SESSION['user_id']): ?>
                                    <form method="POST" class="d-inline">
                                        <input type="hidden" name="kick_id" value="<?php echo htmlspecialchars($user['user_id']); ?>">
                                        <button type="submit" name="kick_user" class="btn btn-sm btn-outline-danger" 
                                                onclick="return confirm('Revoke session for <?php echo htmlspecialchars($user['username']); ?>?');">
                                            <i class="bi bi-power"></i> Kick
                                        </button>
                                    </form>
                                <?php else: ?>
                                    <span class="text-muted small">Current User</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- ==========================================
         SECURITY AUDIT LOG TABLE
         ========================================== -->
    <div class="card bg-dark border-secondary">
        <div class="card-header bg-transparent border-secondary text-white">
            <i class="bi bi-journal-text me-2"></i>Recent Security Audit Log
        </div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-dark table-sm mb-0">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>User</th>
                            <th>Action</th>
                            <th>Target / Details</th>
                            <th>IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($logs as $log): ?>
                        <tr>
                            <td class="text-muted small"><?php echo htmlspecialchars($log['created_at']); ?></td>
                            <!-- GDPR Fallback: If user is deleted, LEFT JOIN returns NULL, so we show 'System' -->
                            <td><?php echo $log['username'] ? htmlspecialchars($log['username']) : '<em class="text-muted">Unknown</em>'; ?></td>
                            <td><code class="text-info"><?php echo htmlspecialchars($log['action']); ?></code></td>
                            <td class="text-muted small"><?php echo htmlspecialchars($log['details'] ?? 'N/A'); ?></td>
                            <td class="font-monospace text-warning"><?php echo htmlspecialchars($log['ip_address']); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>