<?php
/**
 * NetSentinel Network Discovery Page
 * Triggers Python ARP/Ping scan via AJAX and displays
 * live results for agent deployment.
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';

// SECURITY (SR2): Ensure user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$page_title = 'Network Discovery';

// Handle Scan Trigger (via AJAX)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['trigger_scan'])) {
    // Return JSON for AJAX requests
    header('Content-Type: application/json');
    
    try {
        // 1. Fetch configured networks from DB
        $stmt = $pdo->query("SELECT cidr, name, vlan_id FROM networks");
        $networks = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        if (empty($networks)) {
            echo json_encode(['success' => false, 'error' => 'No networks configured.']);
            exit;
        }

        // 2. Prepare JSON payload
        $networks_json = json_encode($networks);

        // 3. PATHS INSIDE THE DOCKER CONTAINER
        $script_path = '/var/www/scripts/discovery.py';
        $python_path = '/usr/bin/python3';

        // Sanity checks for container environment
        if (!file_exists($script_path) || !file_exists($python_path)) {
            echo json_encode(['success' => false, 'error' => 'CRITICAL: Script or Python not found in container.']);
            exit;
        }

        // 4. Execute the command
        // SECURITY (SR3/SR4): CRITICAL - Use escapeshellarg() on the JSON payload.
        // This prevents Command Injection attacks where a malicious user could inject 
        // shell commands (like ; rm -rf /) via the network configuration data.
        $cmd = "$python_path $script_path " . escapeshellarg($networks_json) . " 2>&1";
        
        $output = [];
        $return_var = 0;
        exec($cmd, $output, $return_var);
        $raw_output = implode("\n", $output);

        if ($return_var === 0) {
            $result = json_decode($raw_output, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($result)) {
                echo json_encode([
                    'success' => true,
                    'message' => "Scan completed. Found " . count($result) . " devices.",
                    'devices' => $result
                ]);
            } else {
                echo json_encode(['success' => false, 'error' => "Failed to parse Python output."]);
            }
        } else {
            echo json_encode(['success' => false, 'error' => "Discovery script failed (Exit code: $return_var)."]);
        }
    } catch (PDOException $e) {
        error_log("Discovery DB Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => "Database error."]);
    }
    exit; // Important: exit after JSON response to prevent HTML leakage
}

include __DIR__ . '/includes/header.php';
?>
<!-- HTML remains exactly the same as your current file -->
<div class="container mt-4">
<!-- ... (rest of your HTML) ... -->