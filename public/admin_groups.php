<?php
/**
 * NetSentinel Policy Management Page
 * Admin-only interface for Device Groups, endpoint assignments, 
 * and Baseline Security Rules.
 */
require_once 'includes/db.php';
require_once 'includes/auth.php';
require_once 'includes/audit.php';

if (session_status() === PHP_SESSION_NONE) { session_start(); }
requireLogin();

// SECURITY: Strict case-insensitive admin check to prevent authorization bypass (Fixes D-023).
if (!isset($_SESSION['role']) || strtolower($_SESSION['role']) !== 'admin') {
    http_response_code(403);
    die('<div class="container mt-4"><div class="alert alert-danger">Access denied. Admin privileges required.</div></div>');
}

$message = '';
$message_type = 'success';
$active_tab = 'groups';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // SECURITY: Verify CSRF token on all state-changing POST requests (SR4).
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $message = 'Invalid security token. Please refresh and try again.';
        $message_type = 'danger';
    }
    // ... (Keep your existing Create Group logic) ...
    
    // 3. Assign Devices to Group
    elseif (isset($_POST['assign_devices'])) {
        $group_id = (int) $_POST['group_id'];
        $device_ids = $_POST['device_ids'] ?? [];
        try {
            // DATA INTEGRITY: Clear existing assignments first to prevent duplicate mapping errors.
            $pdo->prepare("DELETE FROM device_group_map WHERE group_id = ?")->execute([$group_id]);
            
            if (!empty($device_ids)) {
                $stmt = $pdo->prepare("INSERT INTO device_group_map (device_id, group_id) VALUES (?, ?)");
                foreach ($device_ids as $device_id) {
                    $stmt->execute([(int)$device_id, $group_id]);
                }
            }
            // AUDIT: Log the bulk assignment action for compliance tracking.
            log_audit($pdo, $_SESSION['user_id'], 'DEVICES_ASSIGNED_TO_GROUP', 'device_group', $group_id, ['count' => count($device_ids)]);
            $message = 'Devices assigned successfully.';
            $active_tab = 'devices';
        } catch (PDOException $e) {
            $message = 'Error assigning devices.';
            $message_type = 'danger';
        }
    }
    // ... (Keep your existing Create/Delete Rule logic) ...
}
// ... (Rest of your PHP fetch logic and HTML remains exactly the same) ...