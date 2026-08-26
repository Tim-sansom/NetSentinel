<?php
/**
 * NetSentinel API Submission Endpoint
 * Receives, validates, and processes JSON telemetry payloads 
 * from Python endpoint agents.
 */

// 1. Enforce JSON response and POST method only
header("Content-Type: application/json");
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["status" => "error", "message" => "Method Not Allowed"]);
    exit;
}

// 2. Bootstrap Core Dependencies
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/findings.php'; // Stateful finding logic

// 3. SR2: AUTHENTICATE - Validate Bearer token
// Prevents unauthorized devices from injecting fake telemetry.
$authenticated_device_uuid = authenticate_api_request($pdo);

// 4. SR3: VALIDATE - Parse and validate JSON payload
// Ensures malformed data doesn't crash the PHP parser or DB.
$payload = validate_json_payload();

// 5. SECURITY CHECK: Prevent UUID Spoofing
// Ensures the authenticated token matches the payload's claimed identity.
if ($payload['device_uuid'] !== $authenticated_device_uuid) {
    http_response_code(403);
    echo json_encode(["status" => "error", "message" => "Token and payload device mismatch"]);
    exit;
}

try {
    // 6. DATA INTEGRITY: Start a database transaction
    // Ensures that if any part of the complex insert fails, the entire run is rolled back.
    // This prevents "ghost" check runs with missing findings.
    $pdo->beginTransaction();

    // 7. UPSERT Device: Find existing or create new
    $stmt = $pdo->prepare("SELECT device_id FROM device WHERE device_uuid = :uuid");
    $stmt->execute(['uuid' => $payload['device_uuid']]);
    $device = $stmt->fetch();

    if ($device) {
        $device_id = $device['device_id'];
        $updateStmt = $pdo->prepare("UPDATE device SET last_seen_at = CURRENT_TIMESTAMP WHERE device_id = :id");
        $updateStmt->execute(['id' => $device_id]);
    } else {
        // New device registration
        $insertStmt = $pdo->prepare("INSERT INTO device (device_uuid, hostname, os_family, os_version, current_health_status)
                                     VALUES (:uuid, :hostname, :os_family, :os_version, 'unknown')");
        $insertStmt->execute([
            'uuid' => $payload['device_uuid'],
            'hostname' => 'unknown', // Updated dynamically by system_info check below
            'os_family' => 'unknown',
            'os_version' => 'unknown'
        ]);
        $device_id = (int) $pdo->lastInsertId();
    }

    // 8. Insert the Check Run record (The parent record for this telemetry batch)
    $runStmt = $pdo->prepare("INSERT INTO check_run (device_id, run_timestamp, overall_status)
                              VALUES (:device_id, :timestamp, 'pending')");
    $runStmt->execute([
        'device_id' => $device_id,
        'timestamp' => $payload['timestamp'] ?? date('Y-m-d H:i:s')
    ]);
    $check_run_id = (int) $pdo->lastInsertId();

    // 9. Process individual check results
    $overall_health = 'healthy'; 
    $observed = []; // Array to hold active stateful findings for this run (NFR1 optimization)

    foreach ($payload['checks'] as $check) {
        $check_name = $check['check_name'] ?? 'unknown';
        $status = $check['status'] ?? 'unknown';
        $severity = $check['severity'] ?? 'info';
        $details = $check['details'] ?? [];

        // Update overall health based on worst-case scenario
        if ($status === 'fail' || $status === 'error') {
            $overall_health = 'unhealthy';
        } elseif ($status === 'warning' && $overall_health !== 'unhealthy') {
            $overall_health = 'warning';
        }

        // Route data to normalised finding tables based on check type
        switch ($check_name) {
            case 'system_info':
                // Update device metadata dynamically
                $sysStmt = $pdo->prepare("UPDATE device SET hostname = :hostname, os_family = :os_family,
                                          os_version = :os_version WHERE device_id = :id");
                $sysStmt->execute([
                    'hostname' => $details['hostname'] ?? 'unknown',
                    'os_family' => $details['os_family'] ?? 'unknown',
                    'os_version' => $details['os_version'] ?? 'unknown',
                    'id' => $device_id
                ]);
                // Insert historical system snapshot
                $sysFindStmt = $pdo->prepare("INSERT INTO system_finding (check_run_id, hostname, os_name, os_version, architecture, uptime_seconds)
                                              VALUES (:check_run_id, :hostname, :os_name, :os_version, :arch, :uptime)");
                $sysFindStmt->execute([
                    'check_run_id' => $check_run_id,
                    'hostname' => $details['hostname'] ?? 'unknown',
                    'os_name' => $details['os_family'] ?? 'unknown',
                    'os_version' => $details['os_version'] ?? 'unknown',
                    'arch' => $details['architecture'] ?? 'unknown',
                    'uptime' => $details['uptime_seconds'] ?? 0
                ]);
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
                        // Flag high-risk ports for the stateful dashboard
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
                $fwStmt = $pdo->prepare("INSERT INTO firewall_finding (check_run_id, profile, enabled, risky_rule_count, status)
                                         VALUES (:check_run_id, :profile, :enabled, :risky, :status)");
                $fwStmt->execute([
                    'check_run_id' => $check_run_id,
                    'profile' => $details['firewall'] ?? $details['os'] ?? 'unknown',
                    'enabled' => $fw_enabled,
                    'risky' => 0,
                    'status' => $status
                ]);
                if ($status === 'fail') {
                    $observed[] = ['finding_key' => 'firewall:disabled', 'severity' => 'high', 'detail' => $details];
                }
                break;

            case 'latency_check':
                $latStmt = $pdo->prepare("INSERT INTO latency_finding (check_run_id, target, latency_ms, status)
                                          VALUES (:check_run_id, :target, :latency, :status)");
                $latStmt->execute([
                    'check_run_id' => $check_run_id,
                    'target' => $details['target'] ?? 'unknown',
                    'latency' => $details['latency_ms'] ?? 0,
                    'status' => $status
                ]);
                break;

            case 'patch_check':
                $patchStmt = $pdo->prepare("INSERT INTO patch_finding (check_run_id, missing_critical_count, missing_important_count, latest_update_count, high_severity_cve_count)
                                            VALUES (:cr, :crit, :imp, :latest, :cve)");
                $patchStmt->execute([
                    'cr' => $check_run_id,
                    'crit' => (int)($details['missing_critical_count'] ?? 0),
                    'imp' => (int)($details['missing_important_count'] ?? 0),
                    'latest' => (int)($details['latest_update_count'] ?? 0),
                    'cve' => (int)($details['high_severity_cve_count'] ?? 0)
                ]);
                if ((int)($details['missing_critical_count'] ?? 0) > 0) {
                    $observed[] = ['finding_key' => 'patch:pending_critical', 'severity' => 'high', 'detail' => ['count' => (int)$details['missing_critical_count']]];
                }
                break;

            case 'log_check':
            case 'persistence_check':
                // Both map to the log_finding table for unified SIEM viewing
                $source = ($check_name === 'log_check') ? ($details['source'] ?? 'unknown') : 'Persistence Check';
                $items = ($check_name === 'log_check') ? ($details['anomalies'] ?? []) : ($details['findings'] ?? []);
                
                if (!empty($items) && is_array($items)) {
                    $logStmt = $pdo->prepare("INSERT INTO log_finding (check_run_id, log_source, anomaly_type, event_count, severity, details)
                                              VALUES (:check_run_id, :source, :type, :count, :severity, :details)");
                    foreach ($items as $item) {
                        $logStmt->execute([
                            'check_run_id' => $check_run_id,
                            'source' => $source,
                            'type' => $item['anomaly_type'] ?? $item['type'] ?? 'unknown',
                            'count' => (int)($item['event_count'] ?? 1),
                            'severity' => $item['severity'] ?? 'info',
                            'details' => json_encode($item['details'] ?? $item)
                        ]);
                        if (in_array(strtolower($item['severity'] ?? ''), ['high', 'critical'])) {
                            $observed[] = [
                                'finding_key' => "log:{$item['anomaly_type']}",
                                'severity'    => strtolower($item['severity']),
                                'detail'      => $item
                            ];
                        }
                    }
                }
                break;
        } // End switch
    } // End foreach

    // 10. NFR1: Process Unified Stateful Findings
    // Upserts active threats and auto-resolves stale ones, keeping the dashboard lightweight.
    record_findings($pdo, $device_id, $observed, 15);

    // 11. FR-POL4: Trigger Policy Engine
    // Evaluates the device against its assigned baseline rules now that all data is in the DB.
    require_once __DIR__ . '/../includes/policy_engine.php';
    evaluate_device_policy($pdo, $device_id, $check_run_id, $payload['checks']);

    // 12. Finalize Transaction
    $updateRunStmt = $pdo->prepare("UPDATE check_run SET overall_status = :status WHERE check_run_id = :id");
    $updateRunStmt->execute(['status' => $overall_health, 'id' => $check_run_id]);
    
    $updateDeviceStmt = $pdo->prepare("UPDATE device SET current_health_status = :status WHERE device_id = :id");
    $updateDeviceStmt->execute(['status' => $overall_health, 'id' => $device_id]);

    $pdo->commit();

    // 13. Return Success
    http_response_code(200);
    echo json_encode([
        "status" => "success",
        "message" => "Telemetry received and stored successfully",
        "check_run_id" => $check_run_id
    ]);

} catch (PDOException $e) {
    // SECURITY: Rollback transaction and log error internally. 
    // Do NOT leak $e->getMessage() to the client, as it may contain DB schema details.
    if ($pdo->inTransaction()) $pdo->rollBack();
    error_log("NetSentinel API DB Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Database processing failed"]);
} catch (Exception $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    error_log("NetSentinel API General Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Internal server error"]);
}
?>