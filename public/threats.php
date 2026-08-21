<?php
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

// Fetch summary stats
$stats = $pdo->query("
    SELECT 
        COUNT(*) as total,
        SUM(is_rce) as rce_count,
        SUM(ransomware_linked) as ransomware_count,
        SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical_count
    FROM vulnerability_feed
    WHERE date_added >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
")->fetch(PDO::FETCH_ASSOC);

include __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2>🛡️ Threat Intelligence</h2>
        <span class="badge bg-info text-dark">
            <i class="bi bi-clock"></i> Auto-updated daily from CISA KEV
        </span>
    </div>

        <!-- Summary Cards -->
    <div class="row mb-4">
        <div class="col-md-3">
            <div class="card bg-danger text-white shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Active Threats (12mo)</h6>
                    <h2 class="fw-bold"><?= number_format($stats['total'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-warning text-dark shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-black-50 text-uppercase small">RCE Threats</h6>
                    <h2 class="fw-bold"><?= number_format($stats['rce_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-dark text-white shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Ransomware-Linked</h6>
                    <h2 class="fw-bold"><?= number_format($stats['ransomware_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-secondary text-white shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-white-50 text-uppercase small">Critical Severity</h6>
                    <h2 class="fw-bold"><?= number_format($stats['critical_count'] ?? 0) ?></h2>
                </div>
            </div>
        </div>
    </div>

    <!-- Threat Table -->
    <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="mb-0">CISA Known Exploited Vulnerabilities</h5>
            <small class="text-muted">Filtered to last 12 months</small>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover table-striped" id="threatTable" style="width:100%">
                    <thead class="table-dark">
                        <tr>
                            <th>CVE ID</th>
                            <th>Vendor / Product</th>
                            <th>Title</th>
                            <th>Due Date</th>
                            <th>Ransomware</th>
                            <th>Badges</th>
                            <th>Matched Devices</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $stmt = $pdo->query("
                            SELECT * FROM vulnerability_feed 
                            WHERE date_added >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
                            ORDER BY date_added DESC
                        ");
                        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)): 
                        ?>
                        <tr>
                            <td>
                                <a href="https://nvd.nist.gov/vuln/detail/<?= htmlspecialchars($row['cve_id']) ?>" 
                                   target="_blank" class="fw-bold text-decoration-none">
                                    <?= htmlspecialchars($row['cve_id']) ?>
                                </a>
                            </td>
                            <td>
                                <strong><?= htmlspecialchars($row['vendor'] ?? 'Unknown') ?></strong><br>
                                <small class="text-muted"><?= htmlspecialchars($row['product'] ?? '') ?></small>
                            </td>
                            <td>
                                <small><?= htmlspecialchars(substr($row['title'] ?? '', 0, 200)) ?><?= strlen($row['title'] ?? '') > 200 ? '...' : '' ?></small>
                            </td>
                            <td>
                                <?php if ($row['due_date']): ?>
                                    <span class="badge bg-<?= strtotime($row['due_date']) < time() ? 'danger' : 'warning' ?>">
                                        <?= htmlspecialchars($row['due_date']) ?>
                                    </span>
                                <?php else: ?>
                                    <span class="text-muted">—</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($row['ransomware_linked']): ?>
                                    <span class="badge bg-danger">Known</span>
                                <?php else: ?>
                                    <span class="badge bg-secondary">Unknown</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($row['is_rce']): ?>
                                    <span class="badge bg-danger">RCE</span>
                                <?php endif; ?>
                                <span class="badge bg-warning text-dark">KEV</span>
                            </td>
                            <td>
                                <span class="badge bg-secondary">
                                    <i class="bi bi-clock"></i> Pending agent matching
                                </span>
                            </td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="mt-3 text-muted small">
        <strong>Data Source:</strong> CISA Known Exploited Vulnerabilities (KEV) Catalogue. 
        Updated daily at 02:00. RCE flagging uses keyword matching on vulnerability descriptions.
        "Matched Devices" will populate once agent software version telemetry is integrated.
    </div>
</div>

<script>
$(document).ready(function() {
    $('#threatTable').DataTable({
        order: [[0, 'dec']],
        pageLength: 25,
        language: {
            search: "Search CVEs, vendors, products, or descriptions:"
        },
        columnDefs: [
            { targets: [2], width: '35%' },
            { targets: [6], orderable: false }
        ]
    });
});
</script>

<?php include __DIR__ . '/includes/footer.php'; ?>