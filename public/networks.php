<?php
/**
 * NetSentinel Network Management Page
 * CRUD operations for target subnets, CIDR ranges, and VLAN configurations.
 * 
 * SECURITY NOTE: Implements Role-Based Access Control (RBAC). 
 * Viewers can see the configured networks, but only Admins can add or delete them.
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

// STEP 4: ROLE CHECK
// Determine if the user is an admin. Viewers can view, but not modify.
$is_admin = (strtolower($_SESSION['role'] ?? '') === 'admin');

$page_title = 'Network Management';
$message = '';
$error = '';

// Handle Form Submissions (Admin ONLY)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    
    if (!$is_admin) {
        $error = "Access Denied: You do not have permission to modify network configurations.";
    } else {
        // 1. Add Network
        if ($_POST['action'] === 'add') {
            $name = trim($_POST['name']);
            $cidr = trim($_POST['cidr']);
            $vlan_id = !empty($_POST['vlan_id']) ? (int)$_POST['vlan_id'] : null;
            $gateway_ip = trim($_POST['gateway_ip']);
            
            if (!empty($name) && !empty($cidr)) {
                try {
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
}

// Fetch existing networks (Visible to all logged-in users)
$stmt = $pdo->query("SELECT * FROM networks ORDER BY network_id DESC");
$networks = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Include header AFTER all PHP logic and redirects are handled
include __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
    <!-- Page Header -->
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h2 class="mb-0">
                <i class="bi bi-globe me-2"></i>Network Management
                <i class="bi bi-question-circle text-muted ms-2" 
                   data-bs-toggle="tooltip" 
                   data-bs-title="Define the subnets and network segments that the NetSentinel discovery script will scan"
                   style="cursor: help; font-size: 0.6em; vertical-align: middle;"></i>
            </h2>
            <p class="text-muted mb-0 mt-1">Configure target ranges to automatically discover unmanaged endpoints</p>
        </div>
        
        <!-- Only show Add button for Admins -->
        <?php if ($is_admin): ?>
            <button class="btn btn-primary" id="addNetworkBtn" data-bs-toggle="modal" data-bs-target="#addNetworkModal">
                <i class="bi bi-plus-circle me-1"></i> Add New Network
            </button>
        <?php else: ?>
            <span class="badge bg-secondary fs-6"><i class="bi bi-eye me-1"></i> View Only</span>
        <?php endif; ?>
    </div>

    <!-- Info Banner -->
    <div class="alert alert-info d-flex align-items-start mb-4" role="alert">
        <i class="bi bi-info-circle-fill me-3 mt-1 fs-5"></i>
        <div>
            <h6 class="alert-heading mb-2">What is Network Management?</h6>
            <p class="mb-2 small">
                This page allows administrators to define the target subnets that the NetSentinel discovery script will scan. 
                By configuring your network ranges here, the system can automatically find unmanaged devices and suggest agent deployment.
            </p>
            <button class="btn btn-sm btn-link p-0 mt-2" type="button" data-bs-toggle="collapse" data-bs-target="#networksHelp" aria-expanded="false"
                    data-bs-toggle="tooltip" data-bs-title="Expand to see configuration guidelines">
                Show how to configure networks
            </button>
            <div class="collapse mt-2" id="networksHelp">
                <div class="card card-body bg-light small">
                    <p class="mb-2"><strong>How to use this page:</strong></p>
                    <ul class="mb-2">
                        <li><strong>Network Name:</strong> A descriptive name for your reference (e.g., "Main Office", "Guest WiFi").</li>
                        <li><strong>CIDR Range:</strong> The subnet to scan, formatted as IP/Prefix (e.g., <code>192.168.1.0/24</code>). This is required for the scan to work.</li>
                        <li><strong>VLAN ID & Gateway:</strong> Optional fields to help document your network topology for future reference and reporting.</li>
                    </ul>
                </div>
            </div>
        </div>
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
        <div class="card-header bg-white py-3">
            <h5 class="mb-0 text-muted">
                Configured Target Networks
                <i class="bi bi-question-circle text-muted ms-2" 
                   data-bs-toggle="tooltip" 
                   data-bs-title="Subnets that will be actively scanned when you trigger Network Discovery"
                   style="cursor: help;"></i>
            </h5>
        </div>
        <div class="card-body">
            <?php if (empty($networks)): ?>
                <div class="text-center py-5">
                    <i class="bi bi-diagram-3 display-4 text-muted"></i>
                    <p class="text-muted mt-3">No networks configured yet. 
                    <?php if ($is_admin): ?>
                        Click "Add New Network" to get started.
                    <?php else: ?>
                        Please contact your administrator to configure target networks.
                    <?php endif; ?>
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
                                <td class="fw-bold"><?= htmlspecialchars($net['name']) ?></td>
                                <td><code><?= htmlspecialchars($net['cidr']) ?></code></td>
                                <td><?= $net['vlan_id'] ? htmlspecialchars($net['vlan_id']) : '<span class="text-muted">N/A</span>' ?></td>
                                <td><?= htmlspecialchars($net['gateway_ip'] ?: 'N/A') ?></td>
                                <td class="text-end">
                                    <?php if ($is_admin): ?>
                                    <form method="POST" action="networks.php" onsubmit="return confirm('Are you sure you want to delete this network? This will remove it from future discovery scans.');">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="network_id" value="<?= $net['network_id'] ?>">
                                        <button type="submit" class="btn btn-sm btn-outline-danger"
                                                data-bs-toggle="tooltip"
                                                data-bs-title="Remove this network from the discovery scan list">
                                            <i class="bi bi-trash"></i> Delete
                                        </button>
                                    </form>
                                    <?php else: ?>
                                    <span class="text-muted small">View Only</span>
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
                        <div class="form-text">
                            <i class="bi bi-info-circle me-1"></i>
                            Used by the Python discovery script to ping/ARP scan the subnet. Format: IP/Prefix (e.g., 192.168.1.0/24).
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label for="vlan_id" class="form-label">VLAN ID</label>
                            <input type="number" class="form-control" id="vlan_id" name="vlan_id" placeholder="e.g., 10">
                            <div class="form-text">Optional documentation field.</div>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label for="gateway_ip" class="form-label">Gateway IP</label>
                            <input type="text" class="form-control" id="gateway_ip" name="gateway_ip" placeholder="e.g., 192.168.1.1">
                            <div class="form-text">Optional documentation field.</div>
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
<?php endif; ?>

<script>
$(document).ready(function() {
    // Initialize Bootstrap Tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            trigger: 'hover',
            placement: 'auto'
        })
    })

    // Initialize tooltip for Add New Network button specifically 
    var addNetworkBtn = document.getElementById('addNetworkBtn');
    if (addNetworkBtn) {
        new bootstrap.Tooltip(addNetworkBtn, {
            title: 'Define a new target subnet for the discovery script to scan',
            placement: 'bottom',
            trigger: 'hover'
        });
    }

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