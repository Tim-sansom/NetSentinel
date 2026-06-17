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

// Include the secure database connection
require_once __DIR__ . '/../includes/db.php';

// 1. Get the raw POST data and decode JSON
$jsonInput = file_get_contents('php://input');
$data = json_decode($jsonInput, true);

if (json_last_error() !== JSON_ERROR_NONE || empty($data)) {
    http_response_code(400);
    echo json_encode(["status" => "error", "message" => "Invalid JSON payload"]);
    exit;
}

// 2. Extract and sanitize data
$hostname = htmlspecialchars($data['hostname'] ?? 'unknown-host', ENT_QUOTES, 'UTF-8');
$os_family = htmlspecialchars($data['system_info']['os_family'] ?? 'Unknown', ENT_QUOTES, 'UTF-8');
$os_version = htmlspecialchars($data['system_info']['os_version'] ?? 'Unknown', ENT_QUOTES, 'UTF-8');
$latency_ms = filter_var($data['latency_ms'] ?? 0, FILTER_VALIDATE_INT) ?: 0;
$overall_status = htmlspecialchars($data['overall_status'] ?? 'Unknown', ENT_QUOTES, 'UTF-8');

try {
    // Start a database transaction (all or nothing)
    $pdo->beginTransaction();

    // 3. UPSERT Device: Find existing device or create a new one
    $stmt = $pdo->prepare("SELECT device_id FROM device WHERE hostname = :hostname");
    $stmt->execute(['hostname' => $hostname]);
    $device = $stmt->fetch();

    if ($device) {
        $device_id = $device['device_id'];
        $updateStmt = $pdo->prepare("UPDATE device SET last_seen_at = CURRENT_TIMESTAMP, current_health_status = :status, os_family = :os_family, os_version = :os_version WHERE device_id = :id");
        $updateStmt->execute([
            'status' => $overall_status,
            'os_family' => $os_family,
            'os_version' => $os_version,
            'id' => $device_id
        ]);
    } else {
        $insertStmt = $pdo->prepare("INSERT INTO device (hostname, os_family, os_version, current_health_status) VALUES (:hostname, :os_family, :os_version, :status)");
        $insertStmt->execute([
            'hostname' => $hostname,
            'os_family' => $os_family,
            'os_version' => $os_version,
            'status' => $overall_status
        ]);
        $device_id = $pdo->lastInsertId();
    }

    // 4. Insert the Check Run record
    $runStmt = $pdo->prepare("INSERT INTO check_run (device_id, latency_ms, overall_status) VALUES (:device_id, :latency_ms, :overall_status)");
    $runStmt->execute([
        'device_id' => $device_id,
        'latency_ms' => $latency_ms,
        'overall_status' => $overall_status
    ]);
    $check_run_id = $pdo->lastInsertId();

    // 5. Insert Port Findings
    if (!empty($data['findings']['ports']) && is_array($data['findings']['ports'])) {
        $portSql = "INSERT INTO port_finding (check_run_id, port_number, protocol, process_name, status, is_expected, severity) 
                    VALUES (:check_run_id, :port_number, :protocol, :process_name, :status, :is_expected, :severity)";
        $portStmt = $pdo->prepare($portSql);
        
        foreach ($data['findings']['ports'] as $port) {
            $portStmt->execute([
                'check_run_id' => $check_run_id,
                'port_number' => (int)($port['port_number'] ?? 0),
                'protocol' => $port['protocol'] ?? 'TCP',
                'process_name' => $port['process_name'] ?? null,
                'status' => $port['status'] ?? 'open',
                'is_expected' => (int)($port['is_expected'] ?? false),
                'severity' => $port['severity'] ?? 'Low'
            ]);
        }
    }

    // 6. Insert Firewall Findings
    if (!empty($data['findings']['firewall']) && is_array($data['findings']['firewall'])) {
        $fw = $data['findings']['firewall'];
        $fwToInsert = isset($fw[0]) ? $fw : [$fw]; 
        
        $fwSql = "INSERT INTO firewall_finding (check_run_id, profile, enabled, risky_rule_count, status) 
                  VALUES (:check_run_id, :profile, :enabled, :risky_rule_count, :status)";
        $fwStmt = $pdo->prepare($fwSql);

        foreach ($fwToInsert as $fwProfile) {
            $fwStmt->execute([
                'check_run_id' => $check_run_id,
                'profile' => $fwProfile['profile'] ?? 'Default',
                'enabled' => (int)($fwProfile['enabled'] ?? false),
                'risky_rule_count' => (int)($fwProfile['risky_rule_count'] ?? 0),
                'status' => $fwProfile['status'] ?? 'Unknown'
            ]);
        }
    }

    // Commit the transaction to MySQL
    $pdo->commit();

    // Return success response to the Python agent
    http_response_code(200);
    echo json_encode([
        "status" => "success", 
        "message" => "Telemetry received and stored successfully",
        "check_run_id" => (int)$check_run_id
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