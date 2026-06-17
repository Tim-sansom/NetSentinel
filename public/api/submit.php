<?php
// public/api/submit.php
// NetSentinel API Endpoint for receiving agent telemetry

header("Content-Type: application/json");

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["status" => "error", "message" => "Method Not Allowed"]);
    exit;
}

// Include the secure database connection and authentication
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';

// 1. AUTHENTICATE: Validate Bearer token (Fulfills SR2)
$authenticated_device_uuid = authenticate_api_request($pdo);

// 2. VALIDATE: Parse and validate JSON payload (Fulfills SR3)
$payload = validate_json_payload();

// 3. SECURITY CHECK: Ensure token UUID matches payload UUID
if ($payload['device_uuid'] !== $authenticated_device_uuid) {
    http_response_code(403);
    echo json_encode(["status" => "error", "message" => "Token and payload device mismatch"]);
    exit;
}

try {
    // Start a database transaction (all or nothing)
    $pdo->beginTransaction();

    // 4. UPSERT Device: Find existing device or create a new one
    $stmt = $pdo->prepare("SELECT device_id FROM device WHERE device_uuid = :uuid");
    $stmt->execute(['uuid' => $payload['device_uuid']]);
    $device = $stmt->fetch();

    if ($device) {
        $device_id = $device['device_id'];
        $updateStmt = $pdo->prepare("UPDATE device SET last_seen_at = CURRENT_TIMESTAMP WHERE device_id = :id");
        $updateStmt->execute(['id' => $device_id]);
    } else {
        // New device - insert with UUID
        $insertStmt = $pdo->prepare("INSERT INTO device (device_uuid, hostname, os_family, os_version, current_health_status) 
                                     VALUES (:uuid, :hostname, :os_family, :os_version, 'unknown')");
        $insertStmt->execute([
            'uuid' => $payload['device_uuid'],
            'hostname' => 'unknown', // Will be updated from system_info check
            'os_family' => 'unknown',
            'os_version' => 'unknown'
        ]);
        $device_id = $pdo->lastInsertId();
    }

    // 5. Insert the Check Run record
    $runStmt = $pdo->prepare("INSERT INTO check_run (device_id, check_timestamp, overall_status) 
                              VALUES (:device_id, :timestamp, 'pending')");
    $runStmt->execute([
        'device_id' => $device_id,
        'timestamp' => $payload['timestamp'] ?? date('Y-m-d H:i:s')
    ]);
    $check_run_id = $pdo->lastInsertId();

    // 6. Process each check result from the agent
    $overall_health = 'healthy'; // Default to healthy
    
    foreach ($payload['checks'] as $check) {
        $check_name = $check['check_name'] ?? 'unknown';
        $status = $check['status'] ?? 'unknown';
        $message = $check['message'] ?? '';
        $severity = $check['severity'] ?? 'info';
        $details = $check['details'] ?? [];
        
        // Update overall health if any check fails
        if ($status === 'fail' || $status === 'error') {
            $overall_health = 'unhealthy';
        } elseif ($status === 'warning' && $overall_health !== 'unhealthy') {
            $overall_health = 'warning';
        }
        
        // Insert into appropriate finding table based on check type
        switch ($check_name) {
            case 'system_info':
                // Update device with system info
                $hostname = $details['hostname'] ?? 'unknown';
                $os_name = $details['os_name'] ?? 'unknown';
                $os_version = $details['os_version'] ?? 'unknown';
                
                $sysStmt = $pdo->prepare("UPDATE device SET hostname = :hostname, os_family = :os_family, 
                                         os_version = :os_version WHERE device_id = :id");
                $sysStmt->execute([
                    'hostname' => $hostname,
                    'os_family' => $os_name,
                    'os_version' => $os_version,
                    'id' => $device_id
                ]);
                
                // Insert system finding
                $sysFindStmt = $pdo->prepare("INSERT INTO system_finding (check_run_id, hostname, os_name, os_version, 
                                             architecture, uptime_seconds) 
                                             VALUES (:check_run_id, :hostname, :os_name, :os_version, :arch, :uptime)");
                $sysFindStmt->execute([
                    'check_run_id' => $check_run_id,
                    'hostname' => $hostname,
                    'os_name' => $os_name,
                    'os_version' => $os_version,
                    'arch' => $details['architecture'] ?? 'unknown',
                    'uptime' => $details['uptime_seconds'] ?? 0
                ]);
                break;
                
            case 'port_check':
                // Insert port findings
                if (!empty($details['open_ports']) && is_array($details['open_ports'])) {
                    $portStmt = $pdo->prepare("INSERT INTO port_finding (check_run_id, port_number, service_name, status, severity) 
                                              VALUES (:check_run_id, :port, :service, :status, :severity)");
                    
                    foreach ($details['open_ports'] as $port) {
                        $portStmt->execute([
                            'check_run_id' => $check_run_id,
                            'port' => $port['port'] ?? 0,
                            'service' => $port['service'] ?? 'unknown',
                            'status' => 'open',
                            'severity' => $severity
                        ]);
                    }
                }
                break;
                
            case 'firewall_check':
                // Insert firewall finding
                $fw_enabled = ($status === 'pass') ? 1 : 0;
                $fwStmt = $pdo->prepare("INSERT INTO firewall_finding (check_run_id, enabled, status, details) 
                                        VALUES (:check_run_id, :enabled, :status, :details)");
                $fwStmt->execute([
                    'check_run_id' => $check_run_id,
                    'enabled' => $fw_enabled,
                    'status' => $status,
                    'details' => json_encode($details)
                ]);
                break;
                
            case 'latency_check':
                // Insert latency finding
                $latency_ms = $details['latency_ms'] ?? 0;
                $latStmt = $pdo->prepare("INSERT INTO latency_finding (check_run_id, target, latency_ms, status) 
                                         VALUES (:check_run_id, :target, :latency, :status)");
                $latStmt->execute([
                    'check_run_id' => $check_run_id,
                    'target' => $details['target'] ?? 'unknown',
                    'latency' => $latency_ms,
                    'status' => $status
                ]);
                break;
        }
    }
    
    // Update check_run with final overall status
    $updateRunStmt = $pdo->prepare("UPDATE check_run SET overall_status = :status WHERE check_run_id = :id");
    $updateRunStmt->execute([
        'status' => $overall_health,
        'id' => $check_run_id
    ]);
    
    // Update device current health status
    $updateDeviceStmt = $pdo->prepare("UPDATE device SET current_health_status = :status WHERE device_id = :id");
    $updateDeviceStmt->execute([
        'status' => $overall_health,
        'id' => $device_id
    ]);

    // Commit the transaction to MySQL
    $pdo->commit();

    // Return success response to the Python agent
    http_response_code(200);
    echo json_encode([
        "status" => "success", 
        "message" => "Telemetry received and stored successfully",
        "check_run_id" => (int)$check_run_id,
        "device_uuid" => $payload['device_uuid']
    ]);

} catch (PDOException $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log("NetSentinel API Processing Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Failed to process telemetry data"]);
}
?>