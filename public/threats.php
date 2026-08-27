<?php

require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireLogin();

$page_title = "Threat Intelligence";
require_once __DIR__ . '/includes/header.php';

try {
    // 1. Fetch Summary Counts for the top cards (Last 12 Months)
    $stmt = $pdo->query("
        SELECT 
            COUNT(*) as total_count,
            SUM(CASE WHEN is_rce = 1 OR severity = 'Critical' THEN 1 ELSE 0 END) as rce_count,
            SUM(CASE WHEN ransomware_linked = 1 THEN 1 ELSE 0 END) as ransomware_count,
            SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical_count
        FROM vulnerability_feed
        WHERE date_added >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
    ");
    $counts = $stmt->fetch(PDO::FETCH_ASSOC);
    
    // 2. Fetch the main threat feed
    // Note: Removed 'vendor_project' to prevent the 1054 Unknown column error. 
    // We use 'product' which is confirmed to exist in your schema.
    $stmt = $pdo->query("
        SELECT 
            cve_id, 
            product, 
            short_description, 
            severity, 
            date_added, 
            due_date
        FROM vulnerability_feed
        WHERE date_added >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
        ORDER BY date_added DESC
        LIMIT 500
    ");
    $threats = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
} catch (PDOException $e) {
    $error = "Database error: " . htmlspecialchars($e->getMessage());
    $threats = [];
    $counts = ['total_count' => 0, 'rce_count' => 0, 'ransomware_count' => 0, 'critical_count' => 0];
}
?>

<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-shield-exclamation text-danger"></i> Threat Intelligence</h2>
        <span class="badge bg-secondary fs-6">Last 12 Months</span>
    </div>

    <?php if (isset($error)): ?>
        <div class="alert alert-danger"><?= $error ?></div>
    <?php endif; ?>

    <!-- KPI Cards -->
    <div class="row mb-4">
        <div class="col-md-3">
            <div class="card bg-primary text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Total Threats</h6>
                    <h2 class="fw-bold"><?= number_format($counts['total_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-danger text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">RCE / Critical</h6>
                    <h2 class="fw-bold"><?= number_format($counts['rce_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-warning text-dark shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-black-50 text-uppercase small">Ransomware Linked</h6>
                    <h2 class="fw-bold"><?= number_format($counts['ransomware_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-dark text-white shadow-sm h-100">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Critical Severity</h6>
                    <h2 class="fw-bold"><?= number_format($counts['critical_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
    </div>

    <!-- Threats Table -->
    <div class="card shadow-sm">
        <div class="card-header bg-white d-flex justify-content-between align-items-center">
            <h5 class="mb-0">Known Exploited Vulnerabilities (CISA KEV)</h5>
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
                                <th>CVE ID</th>
                                <th>Product</th>
                                <th>Description</th>
                                <th>Severity</th>
                                <th>Date Added</th>
                                <th>Due Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($threats as $t): 
                                $sev_class = 'bg-secondary';
                                if ($t['severity'] === 'Critical') $sev_class = 'bg-danger';
                                elseif ($t['severity'] === 'High') $sev_class = 'bg-warning text-dark';
                            ?>
                            <tr>
                                <td class="fw-bold"><?= htmlspecialchars($t['cve_id']) ?></td>
                                <td>
                                    <strong><?= htmlspecialchars($t['product'] ?? 'Unknown') ?></strong>
                                </td>
                                <td><small><?= htmlspecialchars($t['short_description'] ?? 'N/A') ?></small></td>
                                <td>
                                    <span class="badge <?= $sev_class ?>" style="display: inline-block; padding: 0.4em 0.6em; font-size: 0.85em; border-radius: 0.25rem;">
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
    $('#threatsTable').DataTable({
        order: [[4, 'desc']], // Sort by Date Added descending
        pageLength: 25,
        language: {
            search: "Search threats:"
        },
        columnDefs: [
            { targets: [2], width: '30%' } // Give description more space
        ]
    });
});
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>