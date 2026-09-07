<?php
/**
 * NetSentinel - Endpoint Devices Management Page
 * ================================================================================
 * 
 * PURPOSE:
 * Provides a centralized, filtered view of all monitored endpoint devices, 
 * displaying their health status, OS metadata, and last seen telemetry.
 * 
 * ACADEMIC SIGNIFICANCE:
 * This module is a primary demonstration of Multi-Tenant Isolation (SR2). 
 * It ensures that standard users and tenant admins only view devices explicitly 
 * assigned to their `device_group_id`, preventing cross-tenant data leakage.
 * 
 * SECURITY BOUNDARIES:
 * - SR2 (Access Control): Strict Row-Level Security (RLS) enforced on all SELECT queries.
 * - SR3 (Output Sanitisation): All dynamic data is escaped via htmlspecialchars() to prevent XSS.
 * 
 * @author Tim Sansom
 * @version 1.0
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

// ===========================================================================
// DATA RETRIEVAL WITH STRICT ROW-LEVEL SECURITY (SR2)
// ===========================================================================
if ($is_super_admin) {
    // Super Admins have global visibility across all tenants for platform oversight
    $devices_query = "SELECT * FROM device ORDER BY last_seen_at DESC";
    $stmt = $pdo->query($devices_query);
} else {
    if ($user_group_id) {
        // Standard Admins/Viewers: Strictly filter by their assigned tenant group ID
        $stmt = $pdo->prepare("SELECT * FROM device WHERE device_group_id = ? ORDER BY last_seen_at DESC");
        $stmt->execute([$user_group_id]);
    } else {
        // Defensive programming: Return an empty result set for users without an assigned group.
        // This prevents SQL errors or accidental data leakage (e.g., returning all rows).
        $stmt = $pdo->query("SELECT * FROM device WHERE 1=0");
    }
}

$devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
$page_title = "Endpoint Devices";

require_once __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
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
                                    'linux' => 'bg-success', 
                                    'macos' => 'bg-dark', 
                                    default => 'bg-secondary' 
                                };
                            ?>
                                <tr>
                                    <!-- SR3: Escape all dynamic output to prevent Cross-Site Scripting (XSS) -->
                                    <td class="fw-bold"><?= htmlspecialchars($device['hostname'] ?: 'Unknown') ?></td>
                                    <td><span class="badge <?= $os_class ?>"><?= htmlspecialchars($device['os_family'] ?: 'Unknown') ?></span></td>
                                    <td><code><?= htmlspecialchars($device['os_version'] ?: 'Unknown') ?></code></td>
                                    <td><?= date('d M Y, H:i', strtotime($device['last_seen_at'])) ?></td>
                                    <td><?= $status_badge ?></td>
                                    <td>
                                        <a href="device_detail.php?id=<?= (int)$device['device_id'] ?>" class="btn btn-sm btn-outline-primary">
                                            <i class="bi bi-eye me-1"></i>Details
                                        </a>
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

<!-- DataTables Assets (Loaded locally or via CDN as per project config) -->
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css">

<script>
$(document).ready(function() {
    // Initialize DataTables with client-side processing
    // Suitable for MVP scale; can be upgraded to server-side processing (NFR1) if dataset exceeds ~1000 rows
    $('#devicesTable').DataTable({ 
        pageLength: 10, 
        order: [[3, 'desc']], // Default sort by 'Last Seen' descending
        language: { 
            search: "Filter devices:" 
        } 
    });
});
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>