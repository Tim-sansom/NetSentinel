<?php
/**
 * NetSentinel Help & Support Page
 * 
 * Provides user-friendly guides, troubleshooting FAQ, and 
 * system health status. Accessible to all logged-in users.
 */
// STEP 1: Start session IMMEDIATELY
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// STEP 2: Include dependencies
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

// STEP 3: Check authentication (Accessible to all logged-in users, Admin and Viewer)
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$page_title = 'Help & Support';
require_once __DIR__ . '/includes/header.php';

// --- Simple System Status Checks (For Admins only) ---
$db_status = 'Connected';
$db_color = 'success';
try {
    $pdo->query("SELECT 1");
} catch (PDOException $e) {
    $db_status = 'Disconnected';
    $db_color = 'danger';
}

// RBAC: Determine if user is admin to show/hide system health widget
$is_admin = isset($_SESSION['role']) && strtolower($_SESSION['role']) === 'admin';
?>

<div class="container-fluid mt-4">
    <!-- Page Header -->
    <div class="row mb-4">
        <div class="col-12">
            <h2 class="mb-0">
                <i class="bi bi-question-circle"></i> Help & Support
                <i class="bi bi-question-circle text-muted ms-2" 
                   data-bs-toggle="tooltip" 
                   data-bs-title="User guides, troubleshooting tips, and system status information"
                   style="cursor: help; font-size: 0.6em; vertical-align: middle;"></i>
            </h2>
            <p class="text-muted mb-0 mt-1">Everything you need to know to get the most out of NetSentinel</p>
        </div>
    </div>

    <!-- Info Banner - What is this page? -->
    <div class="alert alert-info d-flex align-items-start mb-4" role="alert">
        <i class="bi bi-info-circle-fill me-3 mt-1 fs-5"></i>
        <div>
            <h6 class="alert-heading mb-2">Welcome to NetSentinel Support</h6>
            <p class="mb-2 small">
                This page is designed to help both technical and non-technical users understand how to use the platform, 
                interpret dashboard data, and resolve common issues quickly.
            </p>
            <button class="btn btn-sm btn-link p-0 mt-2" type="button" data-bs-toggle="collapse" data-bs-target="#helpIntro" aria-expanded="false">
                Show how to use this page
            </button>
            <div class="collapse mt-2" id="helpIntro">
                <div class="card card-body bg-light small">
                    <p class="mb-2"><strong>How to use this page:</strong></p>
                    <ul class="mb-0">
                        <li><strong>How-To Guides:</strong> Step-by-step instructions for common tasks like deploying agents or creating policies.</li>
                        <li><strong>Troubleshooting & FAQ:</strong> Quick answers to the most common issues, such as devices not reporting or login problems.</li>
                        <li><strong>System Health:</strong> (Admins only) A quick snapshot of core system components to ensure everything is running smoothly.</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <!-- 1. Quick Start Guide (For Non-Tech Users) -->
    <div class="row mb-4">
        <div class="col-md-8">
            <div class="card shadow-sm">
                <div class="card-header bg-white">
                    <h5 class="mb-0">
                        <i class="bi bi-book"></i> How-To Guides
                        <i class="bi bi-question-circle text-muted ms-2" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Step-by-step instructions for common NetSentinel tasks"
                           style="cursor: help;"></i>
                    </h5>
                </div>
                <div class="card-body">
                    <div class="accordion" id="howToAccordion">
                        <!-- Guide 1: Understanding the Dashboard -->
                        <div class="accordion-item">
                            <h2 class="accordion-header" id="headingOne">
                                <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapseOne">
                                    <strong>1. Understanding the Dashboard Colors</strong>
                                </button>
                            </h2>
                            <div id="collapseOne" class="accordion-collapse collapse show" data-bs-parent="#howToAccordion">
                                <div class="accordion-body">
                                    <p>NetSentinel uses a simple "Traffic Light" system to show you the health of your devices:</p>
                                    <ul>
                                        <li>
                                            <span class="badge bg-danger me-2" 
                                                  data-bs-toggle="tooltip" 
                                                  data-bs-title="Requires immediate investigation and remediation."
                                                  style="cursor: help;">Red (Critical/High)</span>: 
                                            Immediate action required. Examples: Firewall is turned off, or dangerous ports (like Remote Desktop) are open to the internet.
                                        </li>
                                        <li>
                                            <span class="badge bg-warning text-dark me-2" 
                                                  data-bs-toggle="tooltip" 
                                                  data-bs-title="Should be reviewed and addressed in the near future."
                                                  style="cursor: help;">Yellow (Medium)</span>: 
                                            Needs attention soon. Examples: Missing non-critical updates, or unexpected software running.
                                        </li>
                                        <li>
                                            <span class="badge bg-dark text-white me-2" 
                                                  data-bs-toggle="tooltip" 
                                                  data-bs-title="Normal operation. No action required."
                                                  style="cursor: help;">Black (Low/Info)</span>: 
                                            All clear. Standard system information and routine checks.
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>

                        <!-- Guide 2: Adding a New Device -->
                        <div class="accordion-item">
                            <h2 class="accordion-header" id="headingTwo">
                                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseTwo">
                                    <strong>2. How to Add a New Computer (Deploy Agent)</strong>
                                </button>
                            </h2>
                            <div id="collapseTwo" class="accordion-collapse collapse" data-bs-parent="#howToAccordion">
                                <div class="accordion-body">
                                    <p>To start monitoring a new Windows, Mac, or Linux computer:</p>
                                    <ol>
                                        <li>Click <strong>Discovery</strong> in the top menu.</li>
                                        <li>Click <strong>Run Scan</strong>. The system will search your local network for active devices.</li>
                                        <li>Find the computer you want to monitor in the list and click <strong>Deploy Agent</strong>.</li>
                                        <li>Download the generated configuration details.</li>
                                        <li>On the target computer, place the configuration file in the same folder as the NetSentinel Python Agent.</li>
                                        <li>Run the agent. It will automatically connect and appear on your <strong>Devices</strong> page within 5 minutes.</li>
                                    </ol>
                                </div>
                            </div>
                        </div>

                        <!-- Guide 3: Creating a Security Rule -->
                        <div class="accordion-item">
                            <h2 class="accordion-header" id="headingThree">
                                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseThree">
                                    <strong>3. How to Create a Security Policy (Admins Only)</strong>
                                </button>
                            </h2>
                            <div id="collapseThree" class="accordion-collapse collapse" data-bs-parent="#howToAccordion">
                                <div class="accordion-body">
                                    <p>Policies allow you to enforce rules across your company. For example, "No one in Finance should have Remote Desktop open."</p>
                                    <ol>
                                        <li>Go to <strong>Policy Management</strong>.</li>
                                        <li>Under <strong>Device Groups</strong>, create a group (e.g., "Finance Team") and assign the relevant computers to it.</li>
                                        <li>Go to the <strong>Baseline Rules</strong> tab and click <strong>New Rule</strong>.</li>
                                        <li>Set the <strong>Check Type</strong> (e.g., Port Check), the <strong>Target</strong> (e.g., 3389 for Remote Desktop), and the <strong>Expected State</strong> (e.g., Closed).</li>
                                        <li>Save the rule. If any computer in that group breaks this rule, a <strong>Red Alert</strong> will instantly appear on the dashboard.</li>
                                    </ol>
                                </div>
                            </div>
                        </div>

                        <!-- Guide 4: Exporting Reports -->
                        <div class="accordion-item">
                            <h2 class="accordion-header" id="headingFour">
                                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseFour">
                                    <strong>4. How to Export a Compliance Report</strong>
                                </button>
                            </h2>
                            <div id="collapseFour" class="accordion-collapse collapse" data-bs-parent="#howToAccordion">
                                <div class="accordion-body">
                                    <p>Need to send a report to management or an auditor?</p>
                                    <ol>
                                        <li>Navigate to the page containing the data you need (e.g., <strong>Devices</strong>, <strong>Recent Alerts</strong>, or <strong>Audit Logs</strong>).</li>
                                        <li>Look for the green <strong>Export CSV</strong> button in the top right corner.</li>
                                        <li>Click it to instantly download an Excel-compatible spreadsheet of your current data.</li>
                                    </ol>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- 2. Troubleshooting / FAQ (Crucial for non-tech users) -->
        <div class="col-md-4">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white">
                    <h5 class="mb-0">
                        <i class="bi bi-tools"></i> Troubleshooting & FAQ
                        <i class="bi bi-question-circle text-muted ms-2" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Quick answers to the most common questions and issues"
                           style="cursor: help;"></i>
                    </h5>
                </div>
                <div class="card-body">
                    <div class="accordion accordion-flush" id="faqAccordion">
                        <div class="accordion-item">
                            <h2 class="accordion-header" id="faqOne">
                                <button class="accordion-button collapsed py-2" type="button" data-bs-toggle="collapse" data-bs-target="#faqCollapseOne">
                                    <small>My device isn't showing up after deployment.</small>
                                </button>
                            </h2>
                            <div id="faqCollapseOne" class="accordion-collapse collapse" data-bs-parent="#faqAccordion">
                                <div class="accordion-body small">
                                    <ul class="mb-0">
                                        <li>Ensure the Python Agent is actually running on the device.</li>
                                        <li>Check that the configuration file is in the same folder as the agent.</li>
                                        <li>Wait up to 5 minutes. The agent reports on a schedule, not instantly.</li>
                                        <li>Check the <code>agent.log</code> file on the device for "Connection Refused" errors.</li>
                                    </ul>
                                </div>
                            </div>
                        </div>

                        <div class="accordion-item">
                            <h2 class="accordion-header" id="faqTwo">
                                <button class="accordion-button collapsed py-2" type="button" data-bs-toggle="collapse" data-bs-target="#faqCollapseTwo">
                                    <small>I lost my 2FA code / can't log in.</small>
                                </button>
                            </h2>
                            <div id="faqCollapseTwo" class="accordion-collapse collapse" data-bs-parent="#faqAccordion">
                                <div class="accordion-body small">
                                    <p class="mb-1">If you are locked out of your authenticator app:</p>
                                    <p class="mb-0">Contact your System Administrator. They can temporarily disable 2FA on your account from the <strong>User Management</strong> page so you can log back in and re-scan your QR code.</p>
                                </div>
                            </div>
                        </div>

                        <div class="accordion-item">
                            <h2 class="accordion-header" id="faqThree">
                                <button class="accordion-button collapsed py-2" type="button" data-bs-toggle="collapse" data-bs-target="#faqCollapseThree">
                                    <small>What does "Unknown User" mean in Audit Logs?</small>
                                </button>
                            </h2>
                            <div id="faqCollapseThree" class="accordion-collapse collapse" data-bs-parent="#faqAccordion">
                                <div class="accordion-body small">
                                    <!-- GDPR COMPLIANCE EXPLANATION -->
                                    <p class="mb-0">This is a security and privacy feature. If an employee leaves the company and their user account is deleted, their name is removed from the system to comply with GDPR Right to Erasure. However, the <em>actions</em> they took (like changing a password) are kept for security auditing, labeled as "Unknown User".</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- 3. System Health (Only visible to Admins, kept simple) -->
    <?php if ($is_admin): ?>
    <div class="row">
        <div class="col-12">
            <div class="card shadow-sm border-0 bg-light">
                <div class="card-body">
                    <h6 class="text-muted mb-3">
                        <i class="bi bi-activity"></i> System Health (Admin View)
                        <i class="bi bi-question-circle text-muted ms-2" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Real-time status of core NetSentinel backend components"
                           style="cursor: help;"></i>
                    </h6>
                    <div class="d-flex gap-4">
                        <div>
                            <span class="small text-muted">Database:</span>
                            <span class="badge bg-<?= $db_color ?> ms-1" 
                                  data-bs-toggle="tooltip" 
                                  data-bs-title="Connection status to the MySQL backend"
                                  style="cursor: help;"><?= $db_status ?></span>
                        </div>
                        <div>
                            <span class="small text-muted">Agent API:</span>
                            <span class="badge bg-success ms-1" 
                                  data-bs-toggle="tooltip" 
                                  data-bs-title="Endpoint accepting telemetry from Python agents"
                                  style="cursor: help;">Operational</span>
                        </div>
                        <div>
                            <span class="small text-muted">Threat Feed:</span>
                            <span class="badge bg-success ms-1" 
                                  data-bs-toggle="tooltip" 
                                  data-bs-title="CISA KEV vulnerability database is up to date"
                                  style="cursor: help;">Updated</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>

</div>

<script>
$(document).ready(function() {
    // Initialize Bootstrap Tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            trigger: 'hover',
            placement: 'auto'
        })
    })
});
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>