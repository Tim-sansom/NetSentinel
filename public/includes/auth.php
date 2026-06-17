<?php
/**
 * NetSentinel API Authentication
 * Validates Bearer tokens for incoming agent requests.
 * Fulfills SR2.
 */

function authenticate_api_request($pdo) {
    // 1. Check if Authorization header exists
    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(['success' => false, 'error' => 'Missing Authorization header']);
        exit;
    }

    // 2. Check if it's a Bearer token
    $auth_header = $headers['Authorization'];
    if (strpos($auth_header, 'Bearer ') !== 0) {
        http_response_code(401);
        echo json_encode(['success' => false, 'error' => 'Invalid Authorization format. Use Bearer token.']);
        exit;
    }

    // 3. Extract the token
    $token = trim(substr($auth_header, 7));

    if (empty($token)) {
        http_response_code(401);
        echo json_encode(['success' => false, 'error' => 'Empty token provided']);
        exit;
    }

    // 4. Validate token against the database
    // Note: Adjust table/column names if your 01-schema.sql uses different names
    // Assuming a table named `devices` with columns `device_uuid` and `api_token`
    $stmt = $pdo->prepare("SELECT device_uuid FROM devices WHERE api_token = :token LIMIT 1");
    $stmt->execute(['token' => $token]);
    $device = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$device) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Invalid or unauthorized API token']);
        exit;
    }

    // 5. Return the authenticated device UUID for use in the endpoint
    return $device['device_uuid'];
}

/**
 * Validates that the incoming request is valid JSON and contains required fields.
 * Fulfills SR3.
 */
function validate_json_payload() {
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Invalid JSON payload']);
        exit;
    }

    // Basic validation for NetSentinel agent payload
    if (!isset($data['device_uuid']) || !isset($data['checks']) || !is_array($data['checks'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Missing required fields: device_uuid, checks']);
        exit;
    }

    return $data;
}