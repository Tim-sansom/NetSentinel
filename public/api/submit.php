<?php
/**
 * NetSentinel API Submission Endpoint
 * ================================================================================
 *
 * PURPOSE:
 * Receives, validates, and processes JSON telemetry payloads from Python endpoint agents.
 * It acts as the primary ingestion point for the SIEM-style architecture, handling
 * authentication, data validation, and normalized database insertion.
 *
 * ACADEMIC SIGNIFICANCE (Zero-Touch & Hybrid Working):
 * - Supports Zero-Touch Auto-Registration: New devices can submit telemetry without
 *   pre-provisioning, lowering the barrier to entry for SME deployments.
 * - Captures Network Context: Records privacy-preserving network classification
 *   (internal vs. remote) to provide visibility into hybrid-working patterns without
 *   storing sensitive public IP geolocation data (GDPR Data Minimization).
 * - Resilient Ingestion Contract (D-097): The port_check handler is shape-agnostic,
 *   accepting the agent's nested 'all_open_ports' payload, a legacy 'open_ports'
 *   payload, or a flat list, and uses PER-PORT severity so critical/high/low are
 *   stored correctly rather than being flattened to the check-level severity.
 *
 * SECURITY BOUNDARIES:
 * - SR2 (Access Control): Validates Bearer tokens and prevents UUID spoofing.
 * - SR3 (Input Validation): Strict JSON schema validation prevents malformed data injection.
 * - SR4 (Data Integrity): Uses PDO prepared statements and database transactions to
 *   prevent SQL injection and ensure atomic data writes.
 *
 * @author Tim Sansom
 * @version 1.5 (Fixed Zero-Touch Auto-Registration 403 Forbidden for new Linux agents)
 * @date 2026
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

try {
    // 3. VALIDATE PAYLOAD FIRST (So we have the UUID for the auth check)
    $payload = validate_json_payload();

    // Capture the connecting IP address (hybrid-working visibility + audit trails)
    $connecting_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    // 4. ZERO-TOUCH AUTHENTICATION & AUTO-REGISTRATION
    // Extract Bearer token from headers
    $headers = function_exists('getallheaders') ? getallheaders() : [];
    $auth_header = $headers['Authorization'] ?? $headers['authorization'] ?? '';
    $provided_token = '';
    
    if (preg_match('/Bearer\s+(.*)$/i', $auth_header, $matches)) {
        $provided_token = trim($matches[1]);
    }
    
    // Fallback: check payload if header is missing (older agent versions)
    if (empty($provided_token) && isset($payload['api_token'])) {
        $provided_token = $payload['api_token'];
    }

    if (empty($provided_token)) {
        http_response_code(401);
        echo json_encode(["status" => "error", "message" => "Missing API token"]);
        exit;
    }

    // Check if device already exists by UUID
    $stmt = $pdo->prepare("SELECT device_id, device_uuid, token_hash FROM device WHERE device_uuid = ?");
    $stmt->execute([$payload['device_uuid']]);
    $device = $stmt->fetch();

    $token_hash = hash('sha256', $provided_token);

    if ($device) {
        // Existing device: verify token matches
        if ($device['token_hash'] !== $token_hash) {
            http_response_code(403);
            echo json_encode(["status" => "error", "message" => "Invalid token for existing device"]);
            exit;
        }
        $device_id = $device['device_id'];
        
        // Update last seen and IP
        $updateStmt = $pdo->prepare("UPDATE device SET last_seen_at = CURRENT_TIMESTAMP, ip_address = ? WHERE device_id = ?");
        $updateStmt->execute([$connecting_ip, $device_id]);
    } else {
        // NEW DEVICE: Zero-Touch Auto-Registration!
        $insertStmt = $pdo->prepare("INSERT INTO device (device_uuid, hostname, os_family, os_version, current_health_status, token_hash, is_active, ip_address)
            VALUES (:uuid, :hostname, :os_family, :os_version, 'unknown', :token_hash, 1, :ip)");
        $insertStmt->execute([
            'uuid' => $payload['device_uuid'],
            'hostname' => 'unknown', // Will be updated dynamically by system_info check
            'os_family' => 'unknown',
            'os_version' => 'unknown',
            'token_hash' => $token_hash,
            'ip' => $connecting_ip
        ]);
        $device_id = (int) $pdo->lastInsertId();
    }

    // 5. DATA INTEGRITY: Start a database transaction
    $pdo->beginTransaction();

    // 6. Insert the Check Run record (parent record for this telemetry batch)
    $runStmt = $pdo->prepare("INSERT INTO check_run (device_id, run_timestamp, overall_status)
        VALUES (:device_id, :timestamp, 'pending')");
    $runStmt->execute([
        'device_id' => $device_id,
        'timestamp' => $payload['timestamp'] ?? date('Y-m-d H:i:s')
    ]);
    $check_run_id = (int) $pdo->lastInsertId();

    // 7. Process individual check results
    // IMPORTANT: The agent sends 'checks' as a LIST of objects, each with a
    // 'check_name' field. Iterate accordingly (NOT as an associative map).
    $overall_health = 'healthy';
    $observed = [];
    foreach ($payload['checks'] as $check) {
        $check_name = $check['check_name'] ?? 'unknown';
        $status = $check['status'] ?? 'unknown';
        $severity = $check['severity'] ?? 'info';
        $details = $check['details'] ?? [];

        if ($status === 'fail' || $status === 'error') {
            $overall_health = 'unhealthy';
        } elseif ($status === 'warning' && $overall_health !== 'unhealthy') {
            $overall_health = 'warning';
        }

        switch ($check_name) {
            case 'system_info':
                $mac_address = $details['mac_address'] ?? null;
                $network_context = $details['network_context'] ?? 'unknown';
                $ip_address = $details['ip_address'] ?? null;
                $sysStmt = $pdo->prepare("UPDATE device SET
                    hostname = :hostname, os_family = :os_family, os_version = :os_version,
                    ip_address = :ip_address, mac_address = :mac_address, network_context = :network_context
                    WHERE device_id = :id");
                $sysStmt->execute([
                    'hostname' => $details['hostname'] ?? 'unknown',
                    'os_family' => $details['os_family'] ?? 'unknown',
                    'os_version' => $details['os_version'] ?? 'unknown',
                    'ip_address' => $ip_address,
                    'mac_address' => $mac_address,
                    'network_context' => $network_context,
                    'id' => $device_id
                ]);
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

            // --- PORT CHECK (D-097: shape-agnostic + per-port severity) ---
            case 'port_check':
                $open_ports = [];
                if (isset($details['all_open_ports']) && is_array($details['all_open_ports'])) {
                    $open_ports = $details['all_open_ports'];          // agent's real shape
                } elseif (isset($details['open_ports']) && is_array($details['open_ports'])) {
                    $open_ports = $details['open_ports'];               // alternative shape
                } elseif (is_array($details) && array_keys($details) === range(0, count($details) - 1)) {
                    $open_ports = $details;                             // flat-list shape
                }
                if (!empty($open_ports)) {
                    $portStmt = $pdo->prepare("INSERT INTO port_finding
                        (check_run_id, port_number, protocol, process_name, status, severity)
                        VALUES (:check_run_id, :port, :protocol, :process, :status, :severity)");
                    foreach ($open_ports as $port) {
                        $port_num = (int)($port['port'] ?? 0);
                        if ($port_num <= 0) continue;
                        // Per-port severity: agent uses 'risk' (legacy) or 'severity' (new).
                        $port_sev = $port['severity'] ?? $port['risk'] ?? $severity;
                        $portStmt->execute([
                            'check_run_id' => $check_run_id,
                            'port'         => $port_num,
                            'protocol'     => $port['protocol'] ?? 'tcp',
                            'process'      => $port['service'] ?? 'unknown',
                            'status'       => 'open',
                            'severity'     => $port_sev,
                        ]);
                        if (in_array($port_num, [22, 445, 3389], true)) {
                            $observed[] = [
                                'finding_key' => "port:$port_num",
                                'severity'    => ($port_num === 22) ? 'medium' : 'high',
                                'detail'      => $port,
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

    // 8. NFR1: Process Unified Stateful Findings
    record_findings($pdo, $device_id, $observed, 15);

    // 9. FR-POL4: Trigger Policy Engine
    require_once __DIR__ . '/../includes/policy_engine.php';
    evaluate_device_policy($pdo, $device_id, $check_run_id, $payload['checks']);

    // 10. Finalize Transaction
    $updateRunStmt = $pdo->prepare("UPDATE check_run SET overall_status = :status WHERE check_run_id = :id");
    $updateRunStmt->execute(['status' => $overall_health, 'id' => $check_run_id]);
    $updateDeviceStmt = $pdo->prepare("UPDATE device SET current_health_status = :status WHERE device_id = :id");
    $updateDeviceStmt->execute(['status' => $overall_health, 'id' => $device_id]);
    $pdo->commit();

    // 11. Return Success
    http_response_code(200);
    echo json_encode([
        "status" => "success",
        "message" => "Telemetry received and stored successfully",
        "check_run_id" => $check_run_id
    ]);

} catch (PDOException $e) {
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