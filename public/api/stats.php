<?php
header('Content-Type: application/json');

// Mock data for now - will connect to MySQL later
$response = [
    'agents' => 3,
    'vulnerabilities' => 12,
    'secure' => 2,
    'alerts' => 5,
    'vuln_data' => [4, 3, 2, 2, 1],
    'health_data' => [2, 1, 0],
    'alerts' => [
        ['timestamp' => '2026-03-23 10:30:00', 'agent' => 'DESKTOP-ABC', 'type' => 'Open Port 3389', 'severity' => 'High'],
        ['timestamp' => '2026-03-23 10:15:00', 'agent' => 'LAPTOP-XYZ', 'type' => 'Firewall Disabled', 'severity' => 'Critical'],
        ['timestamp' => '2026-03-23 09:45:00', 'agent' => 'SERVER-001', 'type' => 'Outdated OS', 'severity' => 'Medium']
    ]
];

echo json_encode($response);
?>
