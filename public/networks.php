<?php
/**
 * NetSentinel Network Management Page
 * Admin-only CRUD operations for target subnets, CIDR ranges, and VLAN configurations.
 */

// STEP 1: SECURITY - Start session IMMEDIATELY before ANY output.
// This prevents the "headers already sent" error when we need to redirect.
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
<!-- HTML remains exactly the same as your current file -->
<div class="container mt-4">
<!-- ... (rest of your HTML) ... -->