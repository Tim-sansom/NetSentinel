<?php
// STEP 1: Start session IMMEDIATELY
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// STEP 2: Include dependencies
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

// STEP 3: Check authentication (Accessible to all logged-in users)
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$page_title = 'Help & System Status';
require_once __DIR__ . '/includes/header.php';

// --- System Status Checks ---
$db_status = 'Disconnected';
$db_color = 'danger';
try {
    $pdo->query("SELECT 1");
    $db_status = 'Connected';
    $db_color = 'success';
} catch (PDOException $e) {
    $db_status = 'Error';
}

$api_status = file_exists(__DIR__ . '/api/submit.php') ? 'Operational' : 'Missing';
$api_color = file_exists(__DIR__ . '/api/submit.php') ? 'success' : 'danger';
?>

<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-question-circle"></i> Help & System Status</h2>
    </div>

    <!-- 1. System Status Dashboard -->
    <div class="row mb-4">
        <div class="col-md-6">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white"><h5 class="mb-0">System Health</h5></div>
                <div class="card-body">
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            Database (MySQL)
                            <span class="badge bg-<?= $db_color ?>"><?= $db_status ?></span>
                        </li>
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            Agent API (submit.php)
                            <span class="badge bg-<?= $api_color ?>"><?= $api_status ?></span>
                        </li>
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            PHP Version
                            <span class="badge bg-dark"><?= phpversion() ?></span>
                        </li>
                    </ul>
                </div>
            </div>
        </div>

        <!-- 2. Quick Actions -->
        <div class="col-md-6">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white"><h5 class="mb-0">Quick Actions</h5></div>
                <div class="card-body">
                    <a href="admin_users.php" class="btn btn-outline-primary w-100 mb-2"><i class="bi bi-people"></i> Manage Users & Roles</a>
                    <a href="admin_groups.php" class="btn btn-outline-primary w-100 mb-2"><i class="bi bi-shield-check"></i> Configure Policy Rules</a>
                    <a href="audit_logs.php" class="btn btn-outline-primary w-100 mb-2"><i class="bi bi-journal-text"></i> View Audit Logs</a>
                    <a href="export.php?type=devices" class="btn btn-outline-success w-100"><i class="bi bi-download"></i> Export Device Report (CSV)</a>
                </div>
            </div>
        </div>
    </div>

    <!-- 3. User Guide (Accordion) -->
    <div class="card shadow-sm">
        <div class="card-header bg-white"><h5 class="mb-0">NetSentinel User Guide</h5></div>
        <div class="card-body">
            <div class="accordion" id="userGuideAccordion">
                
                <div class="accordion-item">
                    <h2 class="accordion-header" id="headingOne">
                        <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapseOne">
                            <strong>1. Dashboard & Device Monitoring</strong>
                        </button>
                    </h2>
                    <div id="collapseOne" class="accordion-collapse collapse show" data-bs-parent="#userGuideAccordion">
                        <div class="accordion-body">
                            The <strong>Overview</strong> page provides a high-level summary of your network health. Use the <strong>Devices</strong> page to view detailed telemetry for each endpoint. The color-coded badges indicate severity: <span style="background-color: #dc3545; color: white; padding: 2px 6px; border-radius: 4px;">Red</span> for Critical, <span style="background-color: #ffc107; color: black; padding: 2px 6px; border-radius: 4px;">Yellow</span> for High, and <span style="background-color: #212529; color: white; padding: 2px 6px; border-radius: 4px;">Black</span> for Info.
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header" id="headingTwo">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseTwo">
                            <strong>2. Deploying the Python Agent</strong>
                        </button>
                    </h2>
                    <div id="collapseTwo" class="accordion-collapse collapse" data-bs-parent="#userGuideAccordion">
                        <div class="accordion-body">
                            To monitor a new device, navigate to the <strong>Discovery</strong> page and run a network scan. Once a device is identified, click "Deploy Agent". This will generate a unique <code>device_uuid</code> and a secure <code>api_token</code>. Download the configuration file and place it in the same directory as the Python agent on the target endpoint.
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header" id="headingThree">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseThree">
                            <strong>3. Policy Management & Alerts</strong>
                        </button>
                    </h2>
                    <div id="collapseThree" class="accordion-collapse collapse" data-bs-parent="#userGuideAccordion">
                        <div class="accordion-body">
                            Use the <strong>Policy Management</strong> tab to create Device Groups (e.g., "Remote Workers") and assign Baseline Rules (e.g., "Port 3389 must be closed"). If an agent reports a state that violates a rule, a <strong>Policy Violation</strong> is logged and appears on the <strong>Recent Alerts</strong> page.
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header" id="headingFour">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseFour">
                            <strong>4. Security & Audit Logs</strong>
                        </button>
                    </h2>
                    <div id="collapseFour" class="accordion-collapse collapse" data-bs-parent="#userGuideAccordion">
                        <div class="accordion-body">
                            All administrative actions are recorded in the <strong>Audit Log</strong>. If a user is deleted (GDPR Right to Erasure), their name is replaced with "Unknown User" in the logs, but the action record is preserved for security auditing.
                        </div>
                    </div>
                </div>

            </div>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>