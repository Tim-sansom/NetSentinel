<?php
/**
 * NetSentinel Network Management Page
 * Admin-only CRUD operations for target subnets, CIDR ranges, and VLAN configurations.
 */

// STEP 1: SECURITY - Start session IMMEDIATELY before ANY output.
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// STEP 2: Include database
require_once __DIR__ . '/includes/db.php';

// STEP 3: Check authentication BEFORE including header.php
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// STEP 4: STRICT ADMIN CHECK (Fixes D-007)
// Case-insensitive role check. Prevents authorization bypass if the DB stores "Admin" instead of "admin".
if (strtolower($_SESSION['role'] ?? '') !== 'admin') {
    header('Location: dashboard.php');
    exit;
}

$page_title = 'Network Management';
$message = '';
$error = '';

// Handle Form Submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    
    // 1. Add Network
    if ($_POST['action'] === 'add') {
        $name = trim($_POST['name']);
        $cidr = trim($_POST['cidr']);
        $vlan_id = !empty($_POST['vlan_id']) ? (int)$_POST['vlan_id'] : null;
        $gateway_ip = trim($_POST['gateway_ip']);
        
        if (!empty($name) && !empty($cidr)) {
            try {
                // SECURITY (SR3): Prepared statements prevent SQL Injection on CIDR insertion.
                $stmt = $pdo->prepare("INSERT INTO networks (name, cidr, vlan_id, gateway_ip) VALUES (?, ?, ?, ?)");
                $stmt->execute([$name, $cidr, $vlan_id, $gateway_ip]);
                $message = "Network added successfully!";
            } catch (PDOException $e) {
                $error = "Database error: " . $e->getMessage();
                error_log("Network Add Error: " . $e->getMessage());
            }
        } else {
            $error = "Name and CIDR are required.";
        }
    } 
    // 2. Delete Network
    elseif ($_POST['action'] === 'delete') {
        // SECURITY: Cast to integer to prevent SQL injection via ID manipulation
        $network_id = (int)$_POST['network_id'];
        try {
            $stmt = $pdo->prepare("DELETE FROM networks WHERE network_id = ?");
            $stmt->execute([$network_id]);
            $message = "Network deleted successfully.";
        } catch (PDOException $e) {
            $error = "Database error: " . $e->getMessage();
        }
    }
}

// Fetch existing networks
$stmt = $pdo->query("SELECT * FROM networks ORDER BY network_id DESC");
$networks = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Include header AFTER all PHP logic and redirects are handled
include __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>🌐 Network Management</h2>
        <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addNetworkModal">
            <i class="bi bi-plus-circle"></i> Add New Network
        </button>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-success alert-dismissible fade show" role="alert">
            <?= htmlspecialchars($message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>

    <?php if ($error): ?>
        <div class="alert alert-danger alert-dismissible fade show" role="alert">
            <?= htmlspecialchars($error) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>

    <!-- Networks Table -->
    <div class="card shadow-sm">
        <div class="card-header bg-white">
            <h5 class="mb-0">Configured Target Networks</h5>
        </div>
        <div class="card-body">
            <?php if (empty($networks)): ?>
                <div class="text-center py-5">
                    <i class="bi bi-diagram-3 display-4 text-muted"></i>
                    <p class="text-muted mt-3">No networks configured yet. Click "Add New Network" to get started.</p>
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
                                <td class="fw-bold"><?= htmlspecialchars($net['name']) ?></td>
                                <td><code><?= htmlspecialchars($net['cidr']) ?></code></td>
                                <td><?= $net['vlan_id'] ? htmlspecialchars($net['vlan_id']) : '<span class="text-muted">N/A</span>' ?></td>
                                <td><?= htmlspecialchars($net['gateway_ip'] ?: 'N/A') ?></td>
                                <td class="text-end">
                                    <form method="POST" action="networks.php" onsubmit="return confirm('Are you sure you want to delete this network? This will remove it from discovery scans.');">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="network_id" value="<?= $net['network_id'] ?>">
                                        <button type="submit" class="btn btn-sm btn-outline-danger">
                                            <i class="bi bi-trash"></i> Delete
                                        </button>
                                    </form>
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

<!-- Add Network Modal -->
<div class="modal fade" id="addNetworkModal" tabindex="-1" aria-labelledby="addNetworkModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <form method="POST" action="networks.php">
                <input type="hidden" name="action" value="add">
                <div class="modal-header">
                    <h5 class="modal-title" id="addNetworkModalLabel">Add Target Network</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="name" class="form-label">Network Name <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" id="name" name="name" placeholder="e.g., Office LAN" required>
                    </div>
                    <div class="mb-3">
                        <label for="cidr" class="form-label">CIDR Range <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" id="cidr" name="cidr" placeholder="e.g., 192.168.1.0/24" required>
                        <div class="form-text">Used by the Python discovery script to ping/ARP scan the subnet.</div>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label for="vlan_id" class="form-label">VLAN ID</label>
                            <input type="number" class="form-control" id="vlan_id" name="vlan_id" placeholder="e.g., 10">
                        </div>
                        <div class="col-md-6 mb-3">
                            <label for="gateway_ip" class="form-label">Gateway IP</label>
                            <input type="text" class="form-control" id="gateway_ip" name="gateway_ip" placeholder="e.g., 192.168.1.1">
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Network</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    $('#networksTable').DataTable({
        order: [[0, 'asc']],
        pageLength: 10,
        language: {
            search: "Filter networks:"
        },
        columnDefs: [
            { targets: [4], orderable: false } // Disable sorting on Actions column
        ]
    });
});
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>