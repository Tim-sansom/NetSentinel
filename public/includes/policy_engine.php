<?php
/**
 * NetSentinel Policy Engine
 * Evaluates incoming agent telemetry against baseline rules defined for device groups.
 */

/**
 * Evaluates policy rules for a specific device check run.
 * 
 * @param PDO $pdo Database connection
 * @param int $device_id The internal DB device ID
 * @param int $check_run_id The current check run ID
 * @param array $checks_array The 'checks' array from the agent's JSON payload
 */
function evaluate_device_policy(PDO $pdo, int $device_id, int $check_run_id, array $checks_array): void {
    try {
        // 1. Find all groups this device belongs to
        $stmt = $pdo->prepare("
            SELECT gm.group_id FROM device_group_map gm WHERE gm.device_id = ?
        ");
        $stmt->execute([$device_id]);
        $groups = $stmt->fetchAll(PDO::FETCH_COLUMN);

        if (empty($groups)) {
            return; // Device is not in any group, no rules to apply
        }

        // 2. Fetch all rules for these groups
        $placeholders = str_repeat('?,', count($groups) - 1) . '?';
        $stmt = $pdo->prepare("
            SELECT rule_id, check_type, target, expected_state, severity 
            FROM baseline_rule 
            WHERE group_id IN ($placeholders)
        ");
        $stmt->execute($groups);
        $rules = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (empty($rules)) {
            return; // No rules defined for these groups
        }

        // Helper function to find a specific check in the payload array
        $get_check = function($check_name) use ($checks_array) {
            foreach ($checks_array as $check) {
                if (($check['check_name'] ?? '') === $check_name) {
                    return $check;
                }
            }
            return null;
        };

        // 3. Evaluate each rule against the payload
        $insertStmt = $pdo->prepare("
            INSERT INTO policy_violation (check_run_id, device_id, rule_id, details) 
            VALUES (?, ?, ?, ?)
        ");

        foreach ($rules as $rule) {
            $violation_details = null;
            $check_name = $rule['check_type']; // e.g., 'port_check', 'firewall_check'

            $check_data = $get_check($check_name);

            if (!$check_data) {
                continue; // This specific check wasn't performed in this run
            }

            $status = $check_data['status'] ?? 'unknown';
            $details = $check_data['details'] ?? [];

            // --- PORT CHECK LOGIC ---
            if ($rule['check_type'] === 'port_check') {
                $open_ports = $details['open_ports'] ?? [];
                // Extract just the port numbers into a flat array for easy checking
                $open_port_nums = array_map(function($p) { return (int)($p['port'] ?? 0); }, $open_ports);
                $target_port = (int) $rule['target'];
                
                if ($rule['expected_state'] === 'closed' && in_array($target_port, $open_port_nums, true)) {
                    $violation_details = "Port {$target_port} is OPEN (Expected: CLOSED)";
                } elseif ($rule['expected_state'] === 'open' && !in_array($target_port, $open_port_nums, true)) {
                    $violation_details = "Port {$target_port} is CLOSED (Expected: OPEN)";
                }
            }

            // --- FIREWALL CHECK LOGIC ---
            elseif ($rule['check_type'] === 'firewall_check') {
                // In your submit.php, status 'pass' means firewall is enabled
                $is_enabled = ($status === 'pass');
                
                if ($rule['expected_state'] === 'enabled' && !$is_enabled) {
                    $violation_details = "Firewall is DISABLED (Expected: ENABLED)";
                } elseif ($rule['expected_state'] === 'disabled' && $is_enabled) {
                    $violation_details = "Firewall is ENABLED (Expected: DISABLED)";
                }
            }

            // --- SYSTEM CHECK LOGIC ---
            elseif ($rule['check_type'] === 'system_check') {
                $os_version = $details['os_version'] ?? '';
                if (strpos(strtolower($os_version), strtolower($rule['target'])) === false) {
                     $violation_details = "OS Version '{$os_version}' does not match baseline '{$rule['target']}'";
                }
            }

            // 4. If a violation was found, log it to the database
            if ($violation_details !== null) {
                $insertStmt->execute([
                    $check_run_id,
                    $device_id,
                    $rule['rule_id'],
                    $violation_details
                ]);
            }
        }
    } catch (PDOException $e) {
        error_log("Policy Engine Error: " . $e->getMessage());
    }
}
?>