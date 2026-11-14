<?php
/**
 * NetSentinel - Endpoint Devices Management Page
 * ================================================================================
 *
 * PURPOSE:
 * Provides a centralized, filtered view of all monitored endpoint devices,
 * displaying their health status, OS metadata, and last seen telemetry.
 * Includes full CRUD capabilities (specifically Deletion) for administrative control.
 *
 * ACADEMIC SIGNIFICANCE (Multi-Tenant Isolation & Data Integrity):
 * This module is a primary demonstration of Multi-Tenant Isolation (SR2).
 * It enforces strict Row-Level Security (RLS) to ensure standard users and tenant 
 * admins only view devices explicitly assigned to their `device_group_id`. 
 * This prevents the cross-tenant data leakage identified during final evaluation testing.
 *
 * SECURITY BOUNDARIES:
 * - SR2 (Access Control): Strict RLS enforced on SELECT and DELETE queries.
 * - SR3 (Output Sanitisation): All dynamic data is escaped via htmlspecialchars() to prevent XSS.
 * - SR4 (Data Integrity): Deletion cascades to child tables (check_run) to maintain relational integrity.
 *
 * @author Tim Sansom
 * @version 1.2 (Updated for Strict RLS, Delete CRUD, and Academic Notation)
 * @date 2026
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

// Enforce authentication before any data access
requireLogin();

// ===========================================================================
// ROLE AND SCOPE DETERMINATION (SR2)
// ===========================================================================
// Normalize role to lowercase to prevent case-sensitivity bypasses (e.g., "Admin" vs "admin")
$current_role = strtolower($_SESSION['role'] ?? '');
$is_super_admin = ($current_role === 'super_admin');
$is_admin = ($current_role === 'admin' || $is_super_admin);
$user_group_id = $_SESSION['group_id'] ?? null;
$current_user_id = $_SESSION['user_id'] ?? null;

// ===========================================================================
// HANDLE DEVICE DELETION (CRUD - Delete)
// ===========================================================================
if (isset($_GET['delete']) && is_numeric($_GET['delete'])) {
    $delete_id = (int)$_GET['delete'];
    
    // SR2: Verify ownership before allowing deletion
    $checkStmt = $pdo->prepare("SELECT device_group_id, hostname FROM device WHERE device_id = ?");
    $checkStmt->execute([$delete_id]);
    $targetDevice = $checkStmt->fetch(PDO::FETCH_ASSOC);

    if ($targetDevice) {
        // Permission Check: Super Admin OR device belongs to user's group
        if ($is_super_admin || ($user_group_id && $targetDevice['device_group_id'] == $user_group_id)) {
            // SR4: Data Integrity - Delete child records first to satisfy Foreign Key constraints
            $pdo->prepare("DELETE FROM check_run WHERE device_id = ?")->execute([$delete_id]);
            
            // Delete the device record
            $pdo->prepare("DELETE FROM device WHERE device_id = ?")->execute([$delete_id]);
            
            // Optional: Log the action to audit_log if the helper function exists
            if (function_exists('log_audit')) {
                log_audit($pdo, $current_user_id, 'DEVICE_DELETED', 'device', "Deleted device ID: $delete_id ({$targetDevice['hostname']})", $_SERVER['REMOTE_ADDR'] ?? 'unknown');
            }
            
            header("Location: devices.php?deleted=1");
            exit;
        } else {
            header("Location: devices.php?error=permission");
            exit;
        }
    }
}

// ===========================================================================
// DATA RETRIEVAL WITH STRICT ROW-LEVEL SECURITY (SR2)
// ===========================================================================
if ($is_super_admin) {
    // Super Admins have global visibility across all tenants for platform oversight
    $devices_query = "SELECT * FROM device ORDER BY last_seen_at DESC";
    $stmt = $pdo->query($devices_query);
} else {
    if ($user_group_id) {
        // SR2 FIX: Strict Multi-Tenant Isolation. 
        // Standard admins ONLY see devices explicitly assigned to their group.
        // We REMOVED the "OR device_group_id IS NULL" clause to prevent cross-tenant leakage.
        $stmt = $pdo->prepare("SELECT * FROM device WHERE device_group_id = ? ORDER BY last_seen_at DESC");
        $stmt->execute([$user_group_id]);
    } else {
        // Defensive programming: Return an empty result set for users without an assigned group.
        $stmt = $pdo->query("SELECT * FROM device WHERE 1=0");
    }
}
$devices = $stmt->fetchAll(PDO::FETCH_ASSOC);

$page_title = "Endpoint Devices";
require_once __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
    <!-- Success/Error Alerts -->
    <?php if (isset($_GET['deleted'])): ?>
        <div class="alert alert-success alert-dismissible fade show" role="alert">Device deleted successfully.<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>
    <?php endif; ?>
    <?php if (isset($_GET['error'])): ?>
        <div class="alert alert-danger alert-dismissible fade show" role="alert">Access Denied. You do not have permission to perform this action.<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>
    <?php endif; ?>

    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h2 class="mb-0"><i class="bi bi-hdd-network me-2"></i>Endpoint Devices</h2>
            <p class="text-muted mb-0 mt-1">View and manage all monitored devices in your network</p>
        </div>
        <!-- Dynamic counter reflecting the RLS-filtered dataset -->
        <span class="badge bg-primary fs-6"><?= count($devices) ?> Total Devices</span>
    </div>

    <div class="card shadow-sm">
        <div class="card-header bg-white py-3">
            <h5 class="mb-0"><i class="bi bi-list-ul me-2"></i>Registered Endpoints</h5>
        </div>
        <div class="card-body p-0">
            <?php if (empty($devices)): ?>
                <div class="text-center py-5">
                    <i class="bi bi-hdd-network display-4 text-muted"></i>
                    <h5 class="mt-3">No Devices Found</h5>
                    <p class="text-muted">
                        <?php if ($is_admin): ?>
                            No devices registered yet. Deploy the Python agent to begin monitoring.
                        <?php else: ?>
                            Contact your administrator to request device access.
                        <?php endif; ?>
                    </p>
                </div>
            <?php else: ?>
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0" id="devicesTable">
                        <thead class="table-light">
                            <tr>
                                <th>Hostname</th>
                                <th>OS Family</th>
                                <th>OS Version</th>
                                <th>Last Seen</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($devices as $device): 
                                // Calculate heuristic health status based on telemetry recency
                                $last_seen = strtotime($device['last_seen_at']);
                                $hours_since = (time() - $last_seen) / 3600;
                                
                                // Status thresholds: <1hr = Online, <24hr = Idle, >24hr = Offline
                                if ($hours_since < 1) {
                                    $status_badge = '<span class="badge bg-success">Online</span>';
                                } elseif ($hours_since < 24) {
                                    $status_badge = '<span class="badge bg-warning text-dark">Idle</span>';
                                } else {
                                    $status_badge = '<span class="badge bg-secondary">Offline</span>';
                                }
                                
                                // Map OS family to Bootstrap color classes for visual consistency
                                $os_class = match(strtolower($device['os_family'])) {
                                    'windows' => 'bg-primary',
                                    'linux'   => 'bg-success',
                                    'macos'   => 'bg-dark',
                                    default   => 'bg-secondary'
                                };
                            ?>
                            <tr>
                                <!-- SR3: Escape all dynamic output to prevent Cross-Site Scripting (XSS) -->
                                <td class="fw-bold">
                                    <?= htmlspecialchars($device['hostname'] ?: 'Unknown') ?>
                                </td>
                                <td><span class="badge <?= $os_class ?>"><?= htmlspecialchars($device['os_family'] ?: 'Unknown') ?></span></td>
                                <td><code><?= htmlspecialchars($device['os_version'] ?: 'Unknown') ?></code></td>
                                <td><?= date('d M Y, H:i', strtotime($device['last_seen_at'])) ?></td>
                                <td><?= $status_badge ?></td>
                                <td>
                                    <a href="device_detail.php?id=<?= (int)$device['device_id'] ?>" class="btn btn-sm btn-outline-primary me-1">
                                        <i class="bi bi-eye me-1"></i>Details
                                    </a>
                                    <?php if ($is_admin): ?>
                                        <!-- SR2: Delete button restricted to Admin/Super Admin roles -->
                                        <button type="button" class="btn btn-sm btn-outline-danger" onclick="confirmDelete(<?= (int)$device['device_id'] ?>, '<?= htmlspecialchars($device['hostname']) ?>')">
                                            <i class="bi bi-trash"></i>
                                        </button>
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

<!-- Delete Confirmation Modal -->
<div class="modal fade" id="deleteModal" tabindex="-1" aria-labelledby="deleteModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header bg-danger text-white">
        <h5 class="modal-title" id="deleteModalLabel">Confirm Device Deletion</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        Are you sure you want to permanently delete the device <strong id="deviceNameToDelete"></strong>?
        <br><br>
        <small class="text-muted">This will remove all associated check runs and findings from the database.</small>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <a href="#" id="confirmDeleteBtn" class="btn btn-danger">Delete Device</a>
      </div>
    </div>
  </div>
</div>

<!-- DataTables Assets -->
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css">
<script>
$(document).ready(function() {
    // Initialize DataTables with client-side processing
    // NFR1: Suitable for MVP scale; can be upgraded to server-side processing if dataset exceeds ~1000 rows
    $('#devicesTable').DataTable({
        pageLength: 10,
        order: [[3, 'desc']], // Default sort by 'Last Seen' descending
        language: { search: "Filter devices:" }
    });
});

// JavaScript handler for the Delete Modal
function confirmDelete(deviceId, deviceName) {
    document.getElementById('deviceNameToDelete').textContent = deviceName;
    document.getElementById('confirmDeleteBtn').href = 'devices.php?delete=' + deviceId;
    new bootstrap.Modal(document.getElementById('deleteModal')).show();
}
</script>
<?php require_once __DIR__ . '/includes/footer.php'; ?>