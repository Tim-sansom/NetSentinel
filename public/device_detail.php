<?php
require_once 'includes/db.php';
require_once 'includes/auth.php';

// Ensure user is logged in
requireLogin();

// Get device ID from URL
$device_id = $_GET['id'] ?? null;

if (!$device_id) {
    header('Location: devices.php');
    exit;
}

$page_title = "Device Details";
require_once 'includes/header.php';

try {
    // 1. Fetch Device Info
    $stmt = $pdo->prepare("SELECT * FROM device WHERE device_id = ?");
    $stmt->execute([$device_id]);
    $device = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$device) {
        echo '<div class="alert alert-danger">Device not found.</div>';
        require_once 'includes/footer.php';
        exit;
    }

    // 2. Fetch Latency Data for Chart (Last 50 runs from check_run directly)
    $stmt = $pdo->prepare("
        SELECT run_timestamp, latency_ms 
        FROM check_run 
        WHERE device_id = ?
        ORDER BY run_timestamp ASC
        LIMIT 50
    ");
    $stmt->execute([$device_id]);
    $latency_data = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // 3. Fetch Recent Findings (Port and Firewall only, as system_finding is just metadata)
    $stmt = $pdo->prepare("
        SELECT 'Port' as type, 
               CONCAT('Port ', p.port_number, ' (', COALESCE(p.process_name, 'Unknown'), ')') as detail, 
               p.severity, 
               c.run_timestamp 
        FROM port_finding p 
        JOIN check_run c ON p.check_run_id = c.check_run_id 
        WHERE c.device_id = ?
        
        UNION ALL
        
        SELECT 'Firewall' as type, 
               CONCAT('Profile: ', COALESCE(f.profile, 'Unknown'), ' | Risky Rules: ', f.risky_rule_count) as detail, 
               CASE WHEN f.status = 'Warning' THEN 'high' ELSE 'info' END as severity, 
               c.run_timestamp 
        FROM firewall_finding f 
        JOIN check_run c ON f.check_run_id = c.check_run_id 
        WHERE c.device_id = ?
        
        ORDER BY run_timestamp DESC
        LIMIT 50
    ");
    $stmt->execute([$device_id, $device_id]);
    $findings = $stmt->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    $error = "Database error: " . htmlspecialchars($e->getMessage());
}
?>

<!-- Breadcrumb -->
<nav aria-label="breadcrumb">
    <ol class="breadcrumb">
        <li class="breadcrumb-item"><a href="devices.php">Devices</a></li>
        <li class="breadcrumb-item active" aria-current="page"><?= htmlspecialchars($device['hostname'] ?? 'Unknown Device') ?></li>
    </ol>
</nav>

<?php if (isset($error)): ?>
    <div class="alert alert-danger"><?= $error ?></div>
<?php endif; ?>

<!-- Device Header & Info -->
<div class="card mb-4 shadow-sm">
    <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
        <h4 class="mb-0"><?= htmlspecialchars($device['hostname'] ?? 'Unknown Device') ?></h4>
        <span class="badge bg-light text-dark"><?= htmlspecialchars($device['device_uuid'] ?? $device['device_id']) ?></span>
    </div>
    <div class="card-body">
        <div class="row">
            <div class="col-md-3 mb-3">
                <small class="text-muted d-block">Operating System</small>
                <strong><?= htmlspecialchars(($device['os_family'] ?? '') . ' ' . ($device['os_version'] ?? '')) ?></strong>
            </div>
            <div class="col-md-3 mb-3">
                <small class="text-muted d-block">Architecture</small>
                <strong><?= htmlspecialchars($device['architecture'] ?? 'N/A') ?></strong>
            </div>
            <div class="col-md-3 mb-3">
                <small class="text-muted d-block">Last Seen</small>
                <strong><?= $device['last_seen_at'] ? date('d M Y, H:i', strtotime($device['last_seen_at'])) : 'Never' ?></strong>
            </div>
            <div class="col-md-3 mb-3">
                <small class="text-muted d-block">Health Status</small>
                <span class="badge bg-<?= ($device['current_health_status'] ?? '') === 'Warning' ? 'warning text-dark' : 'success' ?>">
                    <?= htmlspecialchars($device['current_health_status'] ?? 'Unknown') ?>
                </span>
            </div>
        </div>
    </div>
</div>

<!-- Charts Section -->
<div class="row mb-4">
    <div class="col-12">
        <div class="card shadow-sm">
            <div class="card-header">
                <h5 class="mb-0">📈 Network Latency Trend (ms)</h5>
            </div>
            <div class="card-body">
                <?php if (empty($latency_data)): ?>
                    <p class="text-muted text-center py-3">No latency data available yet. The agent may need to run a few more cycles.</p>
                <?php else: ?>
                    <canvas id="latencyChart" height="100"></canvas>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<!-- Recent Findings Table -->
<div class="card shadow-sm">
    <div class="card-header bg-warning text-dark">
        <h5 class="mb-0">🛡️ Recent Security Findings</h5>
    </div>
    <div class="card-body">
        <?php if (empty($findings)): ?>
            <p class="text-muted mb-0">No recent security findings for this device.</p>
        <?php else: ?>
            <div class="table-responsive">
                <table id="findingsTable" class="table table-hover align-middle mb-0">
                    <thead class="table-light">
                        <tr>
                            <th>Timestamp</th>
                            <th>Type</th>
                            <th>Detail</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($findings as $finding): 
                            $sev = strtolower($finding['severity'] ?? 'info');
                            $badge = match($sev) {
                                'critical' => 'bg-danger',
                                'high' => 'bg-warning text-dark',
                                'medium' => 'bg-info text-dark',
                                default => 'bg-secondary'
                            };
                        ?>
                            <tr>
                                <td><?= date('d M Y, H:i', strtotime($finding['run_timestamp'])) ?></td>
                                <td><span class="badge bg-secondary"><?= htmlspecialchars($finding['type']) ?></span></td>
                                <td><?= htmlspecialchars($finding['detail']) ?></td>
                                <td>
                                    <span class="badge <?= $badge ?>"><?= ucfirst(htmlspecialchars($finding['severity'] ?? 'Info')) ?></span>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- Scripts for this page -->
<script>
    // 1. Initialize DataTable for Findings
    $(document).ready(function() {
        $('#findingsTable').DataTable({
            "paging": true,
            "searching": true,
            "ordering": true,
            "info": true,
            "pageLength": 10,
            "language": {
                "search": "Filter findings:"
            }
        });
    });

    // 2. Initialize Chart.js for Latency
    <?php if (!empty($latency_data)): ?>
    const ctx = document.getElementById('latencyChart');
    
    // Map PHP data to JS arrays
    const labels = <?= json_encode(array_column($latency_data, 'run_timestamp')) ?>;
    const data = <?= json_encode(array_column($latency_data, 'latency_ms')) ?>;

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Latency (ms)',
                data: data,
                borderColor: 'rgb(75, 192, 192)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                tension: 0.1,
                fill: true
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Milliseconds'
                    }
                }
            }
        }
    });
    <?php endif; ?>
</script>

<?php require_once 'includes/footer.php'; ?>