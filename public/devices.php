<?php
/**
 * NetSentinel Devices Page
 * Renders a DataTables view of all registered endpoints
 * with filtering by hostname, OS, and health status.
 */
require_once 'includes/db.php';
require_once 'includes/auth.php';

// SECURITY (SR2): Enforce session validation.
requireLogin();

$page_title = "Devices";
require_once 'includes/header.php';

// Fetch all devices
try {
    $stmt = $pdo->prepare("
        SELECT device_id, hostname, os_family, os_version, last_seen_at, current_health_status, device_group_id
        FROM device
        ORDER BY last_seen_at DESC
    ");
    $stmt->execute();
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Devices Page Error: " . $e->getMessage());
    $error = "Error fetching devices.";
    $devices = [];
}
?>
<!-- HTML remains exactly the same as your current file -->
<div class="d-flex justify-content-between align-items-center mb-4">
<!-- ... (rest of your HTML) ... -->