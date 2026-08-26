<?php
// STEP 1: Start session IMMEDIATELY - before ANY output
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// STEP 2: Include dependencies
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

// STEP 3: Check authentication BEFORE including header.php
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// Case-insensitive role check
if (strtolower($_SESSION['role'] ?? '') !== 'admin') {
    http_response_code(403);
    die('<div class="container mt-4"><div class="alert alert-danger">Access denied. Admin privileges required.</div></div>');
}

$page_title = 'Audit Logs';

// STEP 4: NOW include header (which outputs HTML)
require_once __DIR__ . '/includes/header.php';

// STEP 5: Fetch audit logs with LEFT JOIN to handle deleted users (GDPR Right to Erasure compliance)
$stmt = $pdo->query("
    SELECT 
        al.created_at AS timestamp, 
        COALESCE(u.username, 'Unknown User') as username, 
        al.action, 
        al.target_type, 
        al.target_id, 
        al.ip_address, 
        al.user_agent
    FROM audit_log al
    LEFT JOIN user u ON al.user_id = u.user_id
    ORDER BY al.created_at DESC
");
$logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-journal-text"></i> System Audit Log</h2>
        <div>
            <!-- Reporting & Export Framework: CSV Export -->
            <a href="export.php?type=audit" class="btn btn-success btn-sm me-2">
                <i class="bi bi-file-earmark-spreadsheet"></i> Export CSV
            </a>
            <span class="badge bg-dark text-white fs-6"><?= count($logs) ?> Total Events</span>
        </div>
    </div>

    <div class="card shadow-sm">
        <div class="card-header bg-white py-3">
            <h5 class="mb-0 text-muted">Administrative & Security Events</h5>
        </div>
        <div class="card-body">
            <?php if (empty($logs)): ?>
                <div class="text-center py-5">
                    <p class="text-muted mb-0">No audit events recorded yet.</p>
                </div>
            <?php else: ?>
                <div class="table-responsive">
                    <table id="auditTable" class="table table-hover align-middle mb-0" style="width:100%">
                        <thead class="table-light">
                            <tr>
                                <th>Timestamp</th>
                                <th>User</th>
                                <th>Action</th>
                                <th>Target</th>
                                <th>IP Address</th>
                                <th>User Agent</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($logs as $log): ?>
                                <tr>
                                    <td class="text-nowrap"><?= date('d M Y, H:i:s', strtotime($log['timestamp'])) ?></td>
                                    <td>
                                        <span style="display: inline-block; background-color: #6c757d; color: #ffffff; padding: 0.4em 0.65em; font-size: 0.85em; font-weight: 600; border-radius: 0.25rem;">
                                            <?= htmlspecialchars($log['username']) ?>
                                        </span>
                                    </td>
                                    <td>
                                        <code class="text-dark bg-light p-1 rounded"><?= htmlspecialchars($log['action']) ?></code>
                                    </td>
                                    <td>
                                        <?php if ($log['target_type']): ?>
                                            <small class="text-muted"><?= htmlspecialchars($log['target_type']) ?> #<?= htmlspecialchars($log['target_id']) ?></small>
                                        <?php else: ?>
                                            <small class="text-muted">-</small>
                                        <?php endif; ?>
                                    </td>
                                    <td><small><?= htmlspecialchars($log['ip_address']) ?></small></td>
                                    <td>
                                        <small class="text-muted" title="<?= htmlspecialchars($log['user_agent']) ?>">
                                            <?= htmlspecialchars(substr($log['user_agent'], 0, 50)) ?><?= strlen($log['user_agent']) > 50 ? '...' : '' ?>
                                        </small>
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

<!-- DataTables Initialization -->
<script>
$(document).ready(function() {
    $('#auditTable').DataTable({
        "paging": true,
        "searching": true,
        "ordering": true,
        "info": true,
        "pageLength": 25,
        "order": [[ 0, "desc" ]],
        "language": {
            "search": "Filter logs by user, action, or IP:"
        }
    });
});
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>