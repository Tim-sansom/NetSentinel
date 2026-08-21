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
require_once __DIR__ . '/../includes/findings.php'; // Stateful finding logic

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
    $runStmt = $pdo->prepare("INSERT INTO check_run (device_id, run_timestamp, overall_status) 
                              VALUES (:device_id, :timestamp, 'pending')");
    $runStmt->execute([
        'device_id' => $device_id,
        'timestamp' => $payload['timestamp'] ?? date('Y-m-d H:i:s')
    ]);
    $check_run_id = $pdo->lastInsertId();

    // 6. Process each check result from the agent
    $overall_health = 'healthy'; // Default to healthy
    $observed = []; // Array to hold active stateful findings for this run
    
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
        
        // Insert into appropriate finding table based on check type (Historical Events)
        switch ($check_name) {
            case 'system_info':
                $hostname = $details['hostname'] ?? 'unknown';
                $os_family = $details['os_family'] ?? 'unknown'; 
                $os_version = $details['os_version'] ?? 'unknown';
                
                $sysStmt = $pdo->prepare("UPDATE device SET hostname = :hostname, os_family = :os_family, 
                                         os_version = :os_version WHERE device_id = :id");
                $sysStmt->execute([
                    'hostname' => $hostname,
                    'os_family' => $os_family,
                    'os_version' => $os_version,
                    'id' => $device_id
                ]);
                
                $sysFindStmt = $pdo->prepare("INSERT INTO system_finding (check_run_id, hostname, os_name, os_version, 
                                             architecture, uptime_seconds) 
                                             VALUES (:check_run_id, :hostname, :os_name, :os_version, :arch, :uptime)");
                $sysFindStmt->execute([
                    'check_run_id' => $check_run_id,
                    'hostname' => $hostname,
                    'os_name' => $os_family, 
                    'os_version' => $os_version,
                    'arch' => $details['architecture'] ?? 'unknown',
                    'uptime' => $details['uptime_seconds'] ?? 0
                ]);

                if (!empty($details['outdated']) || $status === 'warning') {
                    $observed[] = [
                        'finding_key' => 'system:outdated_os',
                        'severity'    => 'medium',
                        'detail'      => ['os' => $os_version]
                    ];
                }
                break;
                
            case 'port_check':
                if (!empty($details['open_ports']) && is_array($details['open_ports'])) {
                    $portStmt = $pdo->prepare("INSERT INTO port_finding (check_run_id, port_number, protocol, process_name, status, severity) 
                                              VALUES (:check_run_id, :port, :protocol, :process, :status, :severity)");
                    
                    foreach ($details['open_ports'] as $port) {
                        $port_num = $port['port'] ?? 0;
                        $portStmt->execute([
                            'check_run_id' => $check_run_id,
                            'port' => $port_num,
                            'protocol' => $port['protocol'] ?? 'tcp',
                            'process' => $port['service'] ?? 'unknown',
                            'status' => 'open',
                            'severity' => $severity
                        ]);

                        if (in_array((int)$port_num, [22, 445, 3389], true)) {
                            $observed[] = [
                                'finding_key' => "port:$port_num",
                                'severity'    => ((int)$port_num === 22) ? 'medium' : 'high',
                                'detail'      => $port
                            ];
                        }
                    }
                }
                break;
                
            case 'firewall_check':
                $fw_enabled = ($status === 'pass') ? 1 : 0;
                $fw_profile = $details['firewall'] ?? $details['os'] ?? 'unknown';
                
                $fwStmt = $pdo->prepare("INSERT INTO firewall_finding (check_run_id, profile, enabled, risky_rule_count, status) 
                                        VALUES (:check_run_id, :profile, :enabled, :risky, :status)");
                $fwStmt->execute([
                    'check_run_id' => $check_run_id,
                    'profile' => $fw_profile,
                    'enabled' => $fw_enabled,
                    'risky' => 0, 
                    'status' => $status
                ]);

                if ($status === 'fail' || $status === 'error') {
                    $observed[] = [
                        'finding_key' => 'firewall:disabled',
                        'severity'    => 'high',
                        'detail'      => $details
                    ];
                } elseif ($status === 'warning' || $status === 'unknown') {
                    $observed[] = [
                        'finding_key' => 'firewall:unknown',
                        'severity'    => 'medium',
                        'detail'      => $details
                    ];
                }
                break;
                
            case 'latency_check':
                $latency_ms = $details['latency_ms'] ?? 0;
                $latStmt = $pdo->prepare("INSERT INTO latency_finding (check_run_id, target, latency_ms, status) 
                                         VALUES (:check_run_id, :target, :latency, :status)");
                $latStmt->execute([
                    'check_run_id' => $check_run_id,
                    'target' => $details['target'] ?? 'unknown',
                    'latency' => $latency_ms,
                    'status' => $status
                ]);

                if (is_numeric($latency_ms) && (float)$latency_ms > 500) {
                    $observed[] = [
                        'finding_key' => 'latency:high',
                        'severity'    => 'low',
                        'detail'      => ['ms' => (float)$latency_ms, 'target' => $details['target'] ?? '']
                    ];
                }
                break;

            case 'patch_check':
                $patchStmt = $pdo->prepare("INSERT INTO patch_finding (check_run_id, missing_critical_count, missing_important_count, latest_update_count, high_severity_cve_count) 
                                            VALUES (:cr, :crit, :imp, :latest, :cve)");
                $patchStmt->execute([
                    'cr'   => $check_run_id,
                    'crit' => (int)($details['missing_critical_count'] ?? 0),
                    'imp'  => (int)($details['missing_important_count'] ?? 0),
                    'latest' => (int)($details['latest_update_count'] ?? 0),
                    'cve'  => (int)($details['high_severity_cve_count'] ?? 0)
                ]);

                if (!($details['os_supported'] ?? true)) {
                    $observed[] = ['finding_key' => 'patch:outdated_os', 'severity' => 'high', 'detail' => ['last_patch_date' => $details['last_patch_date'] ?? null]];
                }
                if ((int)($details['missing_critical_count'] ?? 0) > 0) {
                    $observed[] = ['finding_key' => 'patch:pending_critical', 'severity' => 'high', 'detail' => ['count' => (int)$details['missing_critical_count']]];
                }
                if (!($details['auto_updates'] ?? false)) {
                    $observed[] = ['finding_key' => 'patch:auto_updates_off', 'severity' => 'medium', 'detail' => []];
                }
                break;

            // --- NEW: Log Anomaly Check (Lightweight SIEM) ---
            case 'log_check':
                if (!empty($details['anomalies']) && is_array($details['anomalies'])) {
                    $logStmt = $pdo->prepare("INSERT INTO log_finding (check_run_id, log_source, anomaly_type, event_count, severity, details) 
                                              VALUES (:check_run_id, :source, :type, :count, :severity, :details)");
                    
                    foreach ($details['anomalies'] as $anomaly) {
                        $logStmt->execute([
                            'check_run_id' => $check_run_id,
                            'source' => $anomaly['source'] ?? 'unknown',
                            'type' => $anomaly['anomaly_type'] ?? 'unknown',
                            'count' => (int)($anomaly['event_count'] ?? 0),
                            'severity' => $anomaly['severity'] ?? 'info',
                            'details' => json_encode($anomaly['details'] ?? [])
                        ]);

                        // Push high/critical log events to the stateful findings dashboard
                        if (in_array(strtolower($anomaly['severity'] ?? ''), ['high', 'critical'])) {
                            $observed[] = [
                                'finding_key' => "log:{$anomaly['anomaly_type']}",
                                'severity'    => strtolower($anomaly['severity']),
                                'detail'      => $anomaly
                            ];
                        }
                    }
                }
                break;

            // --- NEW: Persistence Check (Malware/Backdoor detection) ---
            case 'persistence_check':
                if (!empty($details['findings']) && is_array($details['findings'])) {
                    $logStmt = $pdo->prepare("INSERT INTO log_finding (check_run_id, log_source, anomaly_type, event_count, severity, details) 
                                              VALUES (:check_run_id, :source, :type, :count, :severity, :details)");
                    
                    foreach ($details['findings'] as $finding) {
                        $logStmt->execute([
                            'check_run_id' => $check_run_id,
                            'source' => 'Persistence Check',
                            'type' => $finding['type'] ?? 'unknown_persistence',
                            'count' => 1,
                            'severity' => 'high',
                            'details' => json_encode($finding)
                        ]);
                        
                        // Push to stateful dashboard
                        $observed[] = [
                            'finding_key' => "persistence:{$finding['type']}",
                            'severity'    => 'high',
                            'detail'      => $finding
                        ];
                    }
                }
                break;

            // --- NEW: Software Inventory & Server-Side CVE Matching ---
            case 'software_inventory':
                if (!empty($details['software']) && is_array($details['software'])) {
                    // Prepare a query to find RCE/High-severity CVEs matching the product name
                    // Note: Uses 'product' column to match the vulnerability_feed schema
                    $vulnStmt = $pdo->prepare("SELECT cve_id, severity, title FROM vulnerability_feed 
                                               WHERE product LIKE :product AND is_rce = 1");
                    
                    foreach ($details['software'] as $soft) {
                        $productName = $soft['name'] ?? '';
                        $version = $soft['version'] ?? '';
                        
                        if (empty($productName)) continue;

                        // Simple LIKE match (e.g., 'OpenSSH' matches 'OpenSSH 8.2p1')
                        $vulnStmt->execute(['product' => '%' . $productName . '%']);
                        $matches = $vulnStmt->fetchAll(PDO::FETCH_ASSOC);
                        
                        foreach ($matches as $vuln) {
                            // Push matched CVEs directly to the stateful findings dashboard
                            $observed[] = [
                                'finding_key' => "cve:{$vuln['cve_id']}",
                                'severity'    => strtolower($vuln['severity']), // e.g., 'critical', 'high'
                                'detail'      => [
                                    'cve_id' => $vuln['cve_id'],
                                    'product' => $productName,
                                    'version' => $version,
                                    'title' => $vuln['title']
                                ]
                            ];
                        }
                    }
                }
                break;
        }
    }
    
    // Process the unified finding state (Upsert open, auto-resolve stale)
    record_findings($pdo, (int)$device_id, $observed, 15); 
    
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
} catch (Exception $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log("NetSentinel API General Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Internal server error"]);
}
?>