<?php
// STEP 1: Start session IMMEDIATELY - before ANY output
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// STEP 2: Include database
require_once __DIR__ . '/includes/db.php';

// STEP 3: Check authentication BEFORE including header.php
// This prevents the "headers already sent" error
if (!isset($_SESSION['user_id'])) {
    // Not logged in - redirect to login
    header('Location: login.php');
    exit;
}

// Case-insensitive role check
if (strtolower($_SESSION['role'] ?? '') !== 'admin') {
    header('Location: dashboard.php');
    exit;
}

// STEP 4: Now handle form submissions
$page_title = 'Network Management';
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
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
            }
        } else {
            $error = "Name and CIDR are required.";
        }
    } elseif ($_POST['action'] === 'delete') {
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

// STEP 5: Fetch existing networks
$stmt = $pdo->query("SELECT * FROM networks ORDER BY network_id DESC");
$networks = $stmt->fetchAll(PDO::FETCH_ASSOC);

// STEP 6: NOW include header (which outputs HTML)
include __DIR__ . '/includes/header.php';
?>

<div class="container mt-4">
    <h2>🌐 Network Management</h2>
    
    <?php if ($message): ?>
        <div class="alert alert-success alert-dismissible fade show">
            <?= htmlspecialchars($message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>
    
    <?php if ($error): ?>
        <div class="alert alert-danger alert-dismissible fade show">
            <?= htmlspecialchars($error) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <!-- Add Network Form -->
    <div class="card mb-4">
        <div class="card-header bg-primary text-white">
            <h5 class="mb-0">Add New Network</h5>
        </div>
        <div class="card-body">
            <form method="POST">
                <input type="hidden" name="action" value="add">
                <div class="row">
                    <div class="col-md-4 mb-3">
                        <label for="name" class="form-label">Network Name *</label>
                        <input type="text" class="form-control" id="name" name="name" placeholder="e.g., Corporate LAN" required>
                    </div>
                    <div class="col-md-4 mb-3">
                        <label for="cidr" class="form-label">CIDR Range *</label>
                        <input type="text" class="form-control" id="cidr" name="cidr" placeholder="e.g., 192.168.1.0/24" required>
                    </div>
                    <div class="col-md-2 mb-3">
                        <label for="vlan_id" class="form-label">VLAN ID</label>
                        <input type="number" class="form-control" id="vlan_id" name="vlan_id" placeholder="10">
                    </div>
                    <div class="col-md-2 mb-3">
                        <label for="gateway_ip" class="form-label">Gateway IP</label>
                        <input type="text" class="form-control" id="gateway_ip" name="gateway_ip" placeholder="192.168.1.1">
                    </div>
                </div>
                <button type="submit" class="btn btn-success">
                    <i class="bi bi-plus-circle"></i> Add Network
                </button>
            </form>
        </div>
    </div>

    <!-- Networks Table -->
    <div class="card">
        <div class="card-header">
            <h5 class="mb-0">Configured Networks</h5>
        </div>
        <div class="card-body">
            <?php if (empty($networks)): ?>
                <p class="text-muted">No networks configured yet. Use the form above to add your first network.</p>
            <?php else: ?>
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>CIDR</th>
                                <th>VLAN</th>
                                <th>Gateway</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($networks as $net): ?>
                                <tr>
                                    <td><?= htmlspecialchars($net['network_id']) ?></td>
                                    <td><?= htmlspecialchars($net['name']) ?></td>
                                    <td><code><?= htmlspecialchars($net['cidr']) ?></code></td>
                                    <td><?= htmlspecialchars($net['vlan_id'] ?? 'N/A') ?></td>
                                    <td><?= htmlspecialchars($net['gateway_ip'] ?? 'N/A') ?></td>
                                    <td>
                                        <form method="POST" class="d-inline" onsubmit="return confirm('Delete this network?');">
                                            <input type="hidden" name="action" value="delete">
                                            <input type="hidden" name="network_id" value="<?= $net['network_id'] ?>">
                                            <button type="submit" class="btn btn-sm btn-danger">Delete</button>
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

<?php include __DIR__ . '/includes/footer.php'; ?>