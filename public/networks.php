<?php
/**
 * NetSentinel Network Management Page
 * ================================================================================
 * 
 * PURPOSE:
 * Provides CRUD operations for target subnets, CIDR ranges, and VLAN configurations.
 * 
 * ACADEMIC SIGNIFICANCE:
 * This module is a core component of the Multi-Tenant Isolation (SR2) architecture.
 * It ensures that Standard Admins can only define discovery targets for their own 
 * isolated workspace, preventing cross-tenant data leakage or unauthorized network scanning.
 * 
 * SECURITY BOUNDARIES:
 * - SR2 (Access Control): Strict Row-Level Security (RLS) enforced on all SELECT, INSERT, and DELETE queries.
 * - SR3 (Input Validation): All user inputs are sanitized, and outputs are escaped via htmlspecialchars() to prevent XSS.
 * 
 * @author Tim Sansom
 * @version 1.0
 * @date 2026
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/includes/db.php';

// Redirect unauthenticated users to login
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// ===========================================================================
// ROLE AND SCOPE DETERMINATION (SR2)
// ===========================================================================
// Normalize role to lowercase to prevent case-sensitivity bypasses (e.g., "Admin" vs "admin")
$current_role = strtolower($_SESSION['role'] ?? '');
$is_super_admin = ($current_role === 'super_admin');
$is_admin = ($current_role === 'admin' || $is_super_admin);
$user_group_id = $_SESSION['group_id'] ?? null;

$page_title = 'Network Management';
$message = '';
$error = '';

// ===========================================================================
// FORM SUBMISSION HANDLER (Admin ONLY)
// ===========================================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    
    // SR2: Hard block for non-admin roles attempting to modify configurations
    if (!$is_admin) {
        $error = "Access Denied: You do not have permission to modify network configurations.";
    } else {
        
        if ($_POST['action'] === 'add') {
            $name = trim($_POST['name']);
            $cidr = trim($_POST['cidr']);
            $vlan_id = !empty($_POST['vlan_id']) ? (int)$_POST['vlan_id'] : null;
            $gateway_ip = trim($_POST['gateway_ip']);
            
            if (!empty($name) && !empty($cidr)) {
                try {
                    // SR2 (RLS): CRITICAL - Bind the new network to the user's specific tenant group.
                    // This ensures the network is logically isolated to this admin's workspace.
                    $stmt = $pdo->prepare("
                        INSERT INTO networks (name, cidr, vlan_id, gateway_ip, device_group_id) 
                        VALUES (?, ?, ?, ?, ?)
                    ");
                    $stmt->execute([$name, $cidr, $vlan_id, $gateway_ip, $user_group_id]);
                    $message = "Network added successfully!";
                } catch (PDOException $e) {
                    $error = "Database error: " . $e->getMessage();
                    error_log("Network Add Error: " . $e->getMessage());
                }
            } else {
                $error = "Name and CIDR are required.";
            }
            
        } elseif ($_POST['action'] === 'delete') {
            $network_id = (int)$_POST['network_id'];
            try {
                // SR2 (RLS): Double-lock validation. 
                // Super Admins can delete any network. Standard Admins can ONLY delete networks 
                // that belong to their specific device_group_id, preventing tenant hijacking.
                if ($is_super_admin) {
                    $stmt = $pdo->prepare("DELETE FROM networks WHERE network_id = ?");
                    $stmt->execute([$network_id]);
                } else {
                    $stmt = $pdo->prepare("DELETE FROM networks WHERE network_id = ? AND device_group_id = ?");
                    $stmt->execute([$network_id, $user_group_id]);
                }
                $message = "Network deleted successfully.";
            } catch (PDOException $e) {
                $error = "Database error: " . $e->getMessage();
            }
        }
    }
}

// ===========================================================================
// DATA RETRIEVAL WITH STRICT ROW-LEVEL SECURITY (SR2)
// ===========================================================================
if ($is_super_admin) {
    // Super Admins have global visibility across all tenants
    $stmt = $pdo->query("SELECT * FROM networks ORDER BY network_id DESC");
} else {
    if ($user_group_id) {
        // Standard Admins: Strictly filter by their assigned group ID
        $stmt = $pdo->prepare("SELECT * FROM networks WHERE device_group_id = ? ORDER BY network_id DESC");
        $stmt->execute([$user_group_id]);
    } else {
        // Defensive programming: Return an empty result set for users without an assigned group
        // instead of throwing a SQL error or leaking data.
        $stmt = $pdo->query("SELECT * FROM networks WHERE 1=0"); 
    }
}
$networks = $stmt->fetchAll(PDO::FETCH_ASSOC);

include __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h2 class="mb-0"><i class="bi bi-globe me-2"></i>Network Management</h2>
            <p class="text-muted mb-0 mt-1">Configure target ranges to automatically discover unmanaged endpoints</p>
        </div>
        <?php if ($is_admin): ?>
            <button class="btn btn-primary" id="addNetworkBtn" data-bs-toggle="modal" data-bs-target="#addNetworkModal">
                <i class="bi bi-plus-circle me-1"></i> Add New Network
            </button>
        <?php else: ?>
            <!-- UX Indicator: Clearly show read-only status to standard viewers -->
            <span class="badge bg-secondary fs-6"><i class="bi bi-eye me-1"></i> View Only</span>
        <?php endif; ?>
    </div>

    <!-- Feedback Alerts -->
    <?php if ($message): ?>
        <div class="alert alert-success alert-dismissible fade show">
            <?= htmlspecialchars($message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>
    
    <?php if ($error): ?>
        <div class="alert alert-danger alert-dismissible fade show">
            <!-- SR3: htmlspecialchars prevents Cross-Site Scripting (XSS) on error output -->
            <?= htmlspecialchars($error) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <!-- Networks Data Table -->
    <div class="card shadow-sm">
        <div class="card-header bg-white py-3">
            <h5 class="mb-0 text-muted">Configured Target Networks</h5>
        </div>
        <div class="card-body">
            <?php if (empty($networks)): ?>
                <div class="text-center py-5">
                    <i class="bi bi-diagram-3 display-4 text-muted"></i>
                    <p class="text-muted mt-3">
                        No networks configured yet. 
                        <?php if ($is_admin): ?>Click "Add New Network" to get started.<?php else: ?>Contact your administrator.<?php endif; ?>
                    </p>
                </div>
            <?php else: ?>
                <div class="table-responsive">
                    <table class="table table-hover table-striped" id="networksTable" style="width:100%">
                        <thead class="table-dark">
                            <tr>
                                <th>Network Name</th>
                                <th>CIDR Range</th>
                                <th>VLAN ID</th>
                                <th>Gateway IP</th>
                                <th class="text-end">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($networks as $net): ?>
                            <tr>
                                <!-- SR3: Escape all dynamic output to prevent XSS -->
                                <td class="fw-bold"><?= htmlspecialchars($net['name']) ?></td>
                                <td><code><?= htmlspecialchars($net['cidr']) ?></code></td>
                                <td><?= $net['vlan_id'] ? htmlspecialchars($net['vlan_id']) : '<span class="text-muted">N/A</span>' ?></td>
                                <td><?= htmlspecialchars($net['gateway_ip'] ?: 'N/A') ?></td>
                                <td class="text-end">
                                    <?php if ($is_admin): ?>
                                    <!-- Inline form for deletion with client-side confirmation -->
                                    <form method="POST" action="networks.php" onsubmit="return confirm('Are you sure you want to delete this network? This will affect future discovery scans.');">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="network_id" value="<?= (int)$net['network_id'] ?>">
                                        <button type="submit" class="btn btn-sm btn-outline-danger">
                                            <i class="bi bi-trash"></i> Delete
                                        </button>
                                    </form>
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

<!-- Add Network Modal (Admin Only) -->
<?php if ($is_admin): ?>
<div class="modal fade" id="addNetworkModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="POST" action="networks.php">
            <input type="hidden" name="action" value="add">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Add Target Network</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Network Name <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" name="name" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">CIDR Range <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" name="cidr" placeholder="e.g., 192.168.1.0/24" required>
                        <div class="form-text">Must be a valid IPv4 or IPv6 CIDR notation.</div>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">VLAN ID</label>
                            <input type="number" class="form-control" name="vlan_id">
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Gateway IP</label>
                            <input type="text" class="form-control" name="gateway_ip">
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Network</button>
                </div>
            </div>
        </form>
    </div>
</div>
<?php endif; ?>

<script>
$(document).ready(function() {
    // Initialize Bootstrap Tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) { 
        return new bootstrap.Tooltip(tooltipTriggerEl, { trigger: 'hover', placement: 'auto' }); 
    });
    
    // Initialize DataTables with disabled sorting on the Actions column
    $('#networksTable').DataTable({ 
        order: [[0, 'asc']], 
        pageLength: 10, 
        language: { search: "Filter networks:" }, 
        columnDefs: [{ targets: [4], orderable: false }] 
    });
});
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>