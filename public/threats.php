<?php
/**
 * NetSentinel Threat Intelligence Page
 * Displays CISA KEV feed data, RCE/Ransomware KPIs,
 * and CVE details for vulnerability management.
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$page_title = 'Threat Intelligence';

try {
    // Fetch summary stats
    $stats = $pdo->query("
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN is_rce = 1 OR severity = 'Critical' THEN 1 ELSE 0 END) as rce_count,
            SUM(CASE WHEN ransomware_linked = 1 THEN 1 ELSE 0 END) as ransomware_count,
            SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical_count
        FROM vulnerability_feed
        WHERE date_added >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
    ")->fetch(PDO::FETCH_ASSOC);
    
    // Fetch recent threats for the table
    // Using 'title' instead of 'short_description' (which doesn't exist in schema)
    $threats = $pdo->query("
        SELECT 
            cve_id, 
            vendor, 
            product, 
            title,
            severity, 
            date_added, 
            due_date
        FROM vulnerability_feed
        WHERE date_added >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
        ORDER BY date_added DESC
        LIMIT 500
    ")->fetchAll(PDO::FETCH_ASSOC);
    
} catch (PDOException $e) {
    $error = "Database error: " . htmlspecialchars($e->getMessage());
    $stats = ['total' => 0, 'rce_count' => 0, 'ransomware_count' => 0, 'critical_count' => 0];
    $threats = [];
}

include __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
    <!-- Page Header -->
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h2 class="mb-0">
                <i class="bi bi-shield-exclamation text-danger"></i> Threat Intelligence
                <i class="bi bi-question-circle text-muted ms-2" 
                   data-bs-toggle="tooltip" 
                   data-bs-title="Proactive vulnerability management using real-world threat data"
                   style="cursor: help; font-size: 0.6em; vertical-align: middle;"></i>
            </h2>
            <p class="text-muted mb-0 mt-1">Track known exploited vulnerabilities to prioritize your patching efforts</p>
        </div>
        <span class="badge bg-secondary fs-6">Last 12 Months</span>
    </div>

    <!-- Info Banner - What is this page? -->
    <div class="alert alert-info d-flex align-items-start mb-4" role="alert">
        <i class="bi bi-info-circle-fill me-3 mt-1 fs-5"></i>
        <div>
            <h6 class="alert-heading mb-2">What is Threat Intelligence?</h6>
            <p class="mb-2 small">
                This page displays data from the CISA Known Exploited Vulnerabilities (KEV) catalog. 
                Instead of trying to patch every minor issue, this feed helps you proactively identify and fix 
                vulnerabilities that are <strong>actively being exploited in the wild</strong>, allowing you to prioritize your remediation efforts effectively.
            </p>
            <button class="btn btn-sm btn-link p-0 mt-2" type="button" data-bs-toggle="collapse" data-bs-target="#threatsHelp" aria-expanded="false">
                Show how to use this page
            </button>
            <div class="collapse mt-2" id="threatsHelp">
                <div class="card card-body bg-light small">
                    <p class="mb-2"><strong>Understanding the metrics:</strong></p>
                    <ul class="mb-2">
                        <li><strong>RCE / Critical:</strong> Vulnerabilities that allow Remote Code Execution or are rated Critical severity. These are your highest priority.</li>
                        <li><strong>Ransomware Linked:</strong> Vulnerabilities known to be actively used in ransomware campaigns.</li>
                        <li><strong>Due Date:</strong> The deadline by which federal agencies (and ideally your organization) must remediate the vulnerability according to CISA guidelines.</li>
                    </ul>
                    <p class="mb-0"><strong>How to use this page:</strong> Use the search box to quickly find specific vendors (e.g., "Microsoft", "Cisco") or CVE IDs. Sort by "Due Date" to see what needs immediate attention.</p>
                </div>
            </div>
        </div>
    </div>

    <?php if (isset($error)): ?>
        <div class="alert alert-danger"><?= $error ?></div>
    <?php endif; ?>

    <!-- KPI Cards -->
    <div class="row mb-4">
        <div class="col-md-3">
            <div class="card bg-primary text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">
                        Total Threats
                        <i class="bi bi-question-circle ms-1" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="All known exploited vulnerabilities added to the catalog in the last 12 months."
                           style="cursor: help;"></i>
                    </h6>
                    <h2 class="fw-bold"><?= number_format($stats['total'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-danger text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">
                        RCE / Critical
                        <i class="bi bi-question-circle ms-1" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Vulnerabilities allowing Remote Code Execution or rated Critical severity. Highest patching priority."
                           style="cursor: help;"></i>
                    </h6>
                    <h2 class="fw-bold"><?= number_format($stats['rce_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-warning text-dark shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-black-50 text-uppercase small">
                        Ransomware Linked
                        <i class="bi bi-question-circle ms-1" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Vulnerabilities that threat actors are actively using to deploy ransomware."
                           style="cursor: help;"></i>
                    </h6>
                    <h2 class="fw-bold"><?= number_format($stats['ransomware_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-dark text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">
                        Critical Severity
                        <i class="bi bi-question-circle ms-1" 
                           data-bs-toggle="tooltip" 
                           data-bs-title="Total count of vulnerabilities explicitly rated as 'Critical' by the vendor or CISA."
                           style="cursor: help;"></i>
                    </h6>
                    <h2 class="fw-bold"><?= number_format($stats['critical_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
    </div>

    <!-- Threats Table -->
    <div class="card shadow-sm">
        <div class="card-header bg-white d-flex justify-content-between align-items-center py-3">
            <h5 class="mb-0 text-muted">
                Known Exploited Vulnerabilities (CISA KEV)
                <i class="bi bi-question-circle text-muted ms-2" 
                   data-bs-toggle="tooltip" 
                   data-bs-title="The official catalog of vulnerabilities with known active exploitation."
                   style="cursor: help;"></i>
            </h5>
            <small class="text-muted">Showing up to 500 recent entries</small>
        </div>
        <div class="card-body">
            <?php if (empty($threats)): ?>
                <div class="text-center py-5">
                    <i class="bi bi-shield-check display-4 text-success"></i>
                    <p class="text-muted mt-3">No threat intelligence data available for the last 12 months. Run the cron job to update the feed.</p>
                </div>
            <?php else: ?>
                <div class="table-responsive">
                    <table id="threatsTable" class="table table-hover table-striped" style="width:100%">
                        <thead class="table-dark">
                            <tr>
                                <th>
                                    CVE ID
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The Common Vulnerabilities and Exposures identifier for this specific flaw."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    Vendor / Product
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The manufacturer and specific software or hardware affected by this vulnerability."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    Title
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="A brief, descriptive summary of the vulnerability."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    Severity
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The risk level assigned to this vulnerability."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    Date Added
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The date CISA added this vulnerability to the KEV catalog."
                                       style="cursor: help;"></i>
                                </th>
                                <th>
                                    Due Date
                                    <i class="bi bi-question-circle text-muted ms-1" 
                                       data-bs-toggle="tooltip" 
                                       data-bs-title="The deadline by which federal agencies (and ideally your org) must remediate this vulnerability."
                                       style="cursor: help;"></i>
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($threats as $t): 
                                $sev_class = 'bg-secondary';
                                $tooltip_text = 'Informational severity';
                                if ($t['severity'] === 'Critical') {
                                    $sev_class = 'bg-danger';
                                    $tooltip_text = 'Critical: Highest priority for patching.';
                                } elseif ($t['severity'] === 'High') {
                                    $sev_class = 'bg-warning text-dark';
                                    $tooltip_text = 'High: Should be patched soon.';
                                }
                            ?>
                            <tr>
                                <td class="fw-bold"><?= htmlspecialchars($t['cve_id']) ?></td>
                                <td>
                                    <strong><?= htmlspecialchars($t['vendor'] ?? 'Unknown') ?></strong><br>
                                    <small class="text-muted"><?= htmlspecialchars($t['product'] ?? 'N/A') ?></small>
                                </td>
                                <td><small><?= htmlspecialchars($t['title'] ?? 'N/A') ?></small></td>
                                <td>
                                    <span class="badge <?= $sev_class ?>" 
                                          data-bs-toggle="tooltip" 
                                          data-bs-title="<?= $tooltip_text ?>"
                                          style="display: inline-block; padding: 0.4em 0.6em; font-size: 0.85em; border-radius: 0.25rem; cursor: help;">
                                        <?= htmlspecialchars($t['severity'] ?? 'Unknown') ?>
                                    </span>
                                </td>
                                <td><?= date('d M Y', strtotime($t['date_added'])) ?></td>
                                <td><?= date('d M Y', strtotime($t['due_date'])) ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>
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

    $('#threatsTable').DataTable({
        order: [[4, 'desc']], // Sort by Date Added descending
        pageLength: 25,
        language: {
            search: "Search threats:"
        },
        columnDefs: [
            { targets: [2], width: '30%' } // Give title column more space
        ]
    });
});
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>