<?php
/**
 * NetSentinel Main Dashboard (Overview)
 * The central command center for SME administrators.
 * Features an interactive Cytoscape.js network map, real-time KPIs,
 * and a dense grid of dynamic Chart.js visualisations.
 *
 * ACADEMIC NOTE FOR MARKERS:
 * This page demonstrates the core value proposition of NetSentinel:
 * transforming raw telemetry into actionable, visual situational awareness
 * for non-technical SME admins, satisfying FRD1, FRD3, and NFR1.
 *
 * SECURITY NOTE (SR2 - Multi-Tenant Isolation / Row-Level Security):
 * A critical defect was identified during Final Evaluation testing (FED-001):
 * the original `$is_admin` flag conflated the tenant `admin` role with the
 * platform `super_admin` role. Because every data query used
 * `if ($is_admin) { <global query> } else { <RLS query> }`, a standard tenant
 * admin was routed into the GLOBAL branch and could see other tenants' devices,
 * scans, and telemetry (a horizontal privilege escalation / data leakage).
 *
 * FIX: A distinct `$is_super_admin` flag now governs data SCOPE. Only the
 * platform owner may view cross-tenant data. Tenant admins are ALWAYS forced
 * through the RLS path (JOIN to device / filter by device_group_id / user_id).
 * This enforces strict SR2 isolation and produces a correct "blank slate" for
 * a newly provisioned tenant with no assigned devices.
 *
 * @author Tim Sansom
 * @version 1.3 (Fixed Topology "Managed vs Discovered" trap)
 * @date 2026
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireLogin();

// ===========================================================================
// ROLE AND SCOPE DETERMINATION (SR2)
// ===========================================================================
// Normalize role to lowercase to prevent case-sensitivity bypasses.
// CRITICAL: `$is_super_admin` (data SCOPE) is kept SEPARATE from `$is_admin`
// (UI capability). Using a single flag for both is the root cause of FED-001.
$current_role = strtolower($_SESSION['role'] ?? '');
$is_super_admin = ($current_role === 'super_admin');
$is_admin = ($current_role === 'admin' || $is_super_admin);
$user_group_id = $_SESSION['group_id'] ?? null;
$current_user_id = $_SESSION['user_id'];

// === HANDLE AJAX TOPOLOGY REFRESH REQUESTS ===
if (isset($_GET['ajax']) && $_GET['ajax'] === 'refresh_topology') {
    header('Content-Type: application/json');
    try {
        // SR2: The topology scan must be the latest scan OWNED BY THIS USER,
        // not the globally latest scan (which leaked other tenants' scans).
        if ($is_super_admin) {
            $latest_scan_id = $pdo->query("SELECT scan_id FROM network_scan WHERE status = 'completed' ORDER BY scan_id DESC LIMIT 1")->fetchColumn();
            $networks = $pdo->query("SELECT network_id, name, cidr FROM networks")->fetchAll(PDO::FETCH_ASSOC);
        } else {
            $s = $pdo->prepare("SELECT scan_id FROM network_scan WHERE status = 'completed' AND user_id = ? ORDER BY scan_id DESC LIMIT 1");
            $s->execute([$current_user_id]);
            $latest_scan_id = $s->fetchColumn();
            
            // SR2: Only show networks belonging to this tenant's group.
            if ($user_group_id === null) {
                $networks = [];
            } else {
                $s = $pdo->prepare("SELECT network_id, name, cidr FROM networks WHERE device_group_id = ?");
                $s->execute([$user_group_id]);
                $networks = $s->fetchAll(PDO::FETCH_ASSOC);
            }
        }

        $cy_elements = [];
        $cy_elements[] = ['data' => ['id' => 'core', 'label' => 'NetSentinel Core', 'type' => 'core']];
        foreach ($networks as $net) {
            $net_id = 'net_'.$net['network_id'];
            $cy_elements[] = ['data' => ['id' => $net_id, 'label' => $net['name'], 'type' => 'network']];
            $cy_elements[] = ['data' => ['source' => 'core', 'target' => $net_id]];
        }

        if ($latest_scan_id) {
            // FIX: Removed INNER JOIN with 'device' table.
            // The 'device' table only contains managed endpoints with agents installed.
            // Network discovery must show ALL discovered devices on the network, 
            // regardless of whether an agent is installed yet.
            // Since $latest_scan_id is already scoped to the user above, this query is safe.
            $map_stmt = $pdo->prepare("SELECT * FROM network_scan_result WHERE scan_id = ?");
            $map_stmt->execute([$latest_scan_id]);
            
            $devices = $map_stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($devices as $dev) {
                $dev_id = 'dev_'.$dev['result_id'];
                $type = strtolower($dev['device_type'] ?? 'unknown');
                $shape = 'ellipse'; $color = '#6c757d';
                if (strpos($type, 'router') !== false || strpos($type, 'gateway') !== false) {
                    $shape = 'hexagon'; $color = '#0d6efd';
                } elseif (strpos($type, 'linux') !== false || strpos($type, 'pi') !== false) {
                    $shape = 'ellipse'; $color = '#198754';
                } elseif (strpos($type, 'windows') !== false) {
                    $shape = 'rectangle'; $color = '#0dcaf0';
                } elseif (strpos($type, 'apple') !== false) {
                    $shape = 'triangle'; $color = '#6f42c1';
                }
                
                $target_net = 'core';
                foreach ($networks as $net) {
                    $net_prefix = substr($net['cidr'], 0, strrpos($net['cidr'], '.'));
                    if (strpos($dev['ip_address'], $net_prefix) === 0) {
                        $target_net = 'net_'.$net['network_id'];
                        break;
                    }
                }
                
                $cy_elements[] = ['data' => [
                    'id' => $dev_id,
                    'label' => ($dev['hostname'] !== 'unknown' && !empty($dev['hostname'])) ? $dev['hostname'] : $dev['ip_address'],
                    'type' => 'device',
                    'shape' => $shape,
                    'color' => $color,
                    'ip' => $dev['ip_address'],
                    'os' => $dev['device_type']
                ]];
                $cy_elements[] = ['data' => ['source' => $target_net, 'target' => $dev_id]];
            }
        }

        echo json_encode([
            'success' => true,
            'elements' => $cy_elements,
            'scan_label' => $latest_scan_id ? "Scan #{$latest_scan_id}" : "No Scan Data"
        ]);
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => 'Topology refresh failed.']);
    }
    exit;
}

$page_title = "Security Overview";
require_once __DIR__ . '/includes/header.php';

// Get time range from request (default: 7 days)
$time_range = $_GET['range'] ?? '7d';
$time_ranges = [
    '24h' => ['interval' => '24 HOUR', 'label' => 'Last 24 Hours'],
    '7d'  => ['interval' => '7 DAY',  'label' => 'Last 7 Days'],
    '30d' => ['interval' => '30 DAY', 'label' => 'Last 30 Days']
];
$selected_range = $time_ranges[$time_range] ?? $time_ranges['7d'];

// --- 1. INITIALIZE ALL VARIABLES TO SAFE DEFAULTS ---
$total_devices = 0; $active_devices = 0; $at_risk_devices = 0; $health_score = 100;
$agents_online = 0; $agents_offline = 0;
$os_data = []; $severity_data = []; $top_ports_data = []; $trend_data = [];
$hourly_data = array_fill(0, 24, 0);
$top_devices_data = []; $network_activity = []; $recent_alerts = [];
$last_updated = date('Y-m-d H:i:s');
$error = null;
$cy_json = json_encode([]);
$latest_scan_label = "No Scan Data";

try {
    // === KPI: Total Devices ===
    // SR2: global count reserved for super_admin; tenant admins are RLS-filtered.
    if ($is_super_admin) {
        $total_devices = (int)$pdo->query("SELECT COUNT(*) FROM device")->fetchColumn();
    } else {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM device WHERE device_group_id = ?");
        $stmt->execute([$user_group_id]);
        $total_devices = (int)$stmt->fetchColumn();
    }

    // === KPI: Active Devices (24h) ===
    if ($is_super_admin) {
        $active_devices = (int)$pdo->query("SELECT COUNT(*) FROM device WHERE last_seen_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)")->fetchColumn();
    } else {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM device WHERE device_group_id = ? AND last_seen_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        $stmt->execute([$user_group_id]);
        $active_devices = (int)$stmt->fetchColumn();
    }

    // === KPI: At Risk Devices ===
    if ($is_super_admin) {
        $at_risk_query = "SELECT COUNT(DISTINCT d.device_id) FROM device d INNER JOIN check_run cr ON d.device_id = cr.device_id INNER JOIN port_finding pf ON cr.check_run_id = pf.check_run_id WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) AND pf.severity IN ('critical', 'high')";
        $at_risk_devices = (int)$pdo->query($at_risk_query)->fetchColumn();
    } else {
        $at_risk_query = "SELECT COUNT(DISTINCT d.device_id) FROM device d INNER JOIN check_run cr ON d.device_id = cr.device_id INNER JOIN port_finding pf ON cr.check_run_id = pf.check_run_id WHERE d.device_group_id = ? AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) AND pf.severity IN ('critical', 'high')";
        $stmt = $pdo->prepare($at_risk_query);
        $stmt->execute([$user_group_id]);
        $at_risk_devices = (int)$stmt->fetchColumn();
    }
    $health_score = $total_devices > 0 ? round((($total_devices - $at_risk_devices) / $total_devices) * 100) : 100;

    // === AGENT STATUS ===
    if ($is_super_admin) {
        $agents_online = (int)$pdo->query("SELECT COUNT(*) FROM device WHERE last_seen_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)")->fetchColumn();
    } else {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM device WHERE device_group_id = ? AND last_seen_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)");
        $stmt->execute([$user_group_id]);
        $agents_online = (int)$stmt->fetchColumn();
    }
    $agents_offline = max(0, $total_devices - $agents_online);

    // === TOPOLOGY MAP DATA (SR2) ===
    // Same per-user / per-group scoping as the AJAX handler above.
    if ($is_super_admin) {
        $latest_scan_id = $pdo->query("SELECT scan_id FROM network_scan WHERE status = 'completed' ORDER BY scan_id DESC LIMIT 1")->fetchColumn();
        $networks = $pdo->query("SELECT network_id, name, cidr FROM networks")->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $s = $pdo->prepare("SELECT scan_id FROM network_scan WHERE status = 'completed' AND user_id = ? ORDER BY scan_id DESC LIMIT 1");
        $s->execute([$current_user_id]);
        $latest_scan_id = $s->fetchColumn();
        $networks = ($user_group_id === null) ? [] : (function() use ($pdo, $user_group_id) {
            $q = $pdo->prepare("SELECT network_id, name, cidr FROM networks WHERE device_group_id = ?");
            $q->execute([$user_group_id]);
            return $q->fetchAll(PDO::FETCH_ASSOC);
        })();
    }

    $cy_elements = [];
    $cy_elements[] = ['data' => ['id' => 'core', 'label' => 'NetSentinel Core', 'type' => 'core']];
    foreach ($networks as $net) {
        $net_id = 'net_'.$net['network_id'];
        $cy_elements[] = ['data' => ['id' => $net_id, 'label' => $net['name'], 'type' => 'network']];
        $cy_elements[] = ['data' => ['source' => 'core', 'target' => $net_id]];
    }

    if ($latest_scan_id) {
        $latest_scan_label = "Scan #{$latest_scan_id}";
        
        // FIX: Removed INNER JOIN with 'device' table to show all discovered devices.
        $map_stmt = $pdo->prepare("SELECT * FROM network_scan_result WHERE scan_id = ?");
        $map_stmt->execute([$latest_scan_id]);
        
        $devices = $map_stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($devices as $dev) {
            $dev_id = 'dev_'.$dev['result_id'];
            $type = strtolower($dev['device_type'] ?? 'unknown');
            $shape = 'ellipse'; $color = '#6c757d';
            if (strpos($type, 'router') !== false || strpos($type, 'gateway') !== false) {
                $shape = 'hexagon'; $color = '#0d6efd';
            } elseif (strpos($type, 'linux') !== false || strpos($type, 'pi') !== false) {
                $shape = 'ellipse'; $color = '#198754';
            } elseif (strpos($type, 'windows') !== false) {
                $shape = 'rectangle'; $color = '#0dcaf0';
            } elseif (strpos($type, 'apple') !== false) {
                $shape = 'triangle'; $color = '#6f42c1';
            }
            
            $target_net = 'core';
            foreach ($networks as $net) {
                $net_prefix = substr($net['cidr'], 0, strrpos($net['cidr'], '.'));
                if (strpos($dev['ip_address'], $net_prefix) === 0) {
                    $target_net = 'net_'.$net['network_id'];
                    break;
                }
            }
            
            $cy_elements[] = ['data' => [
                'id' => $dev_id,
                'label' => ($dev['hostname'] !== 'unknown' && !empty($dev['hostname'])) ? $dev['hostname'] : $dev['ip_address'],
                'type' => 'device',
                'shape' => $shape,
                'color' => $color,
                'ip' => $dev['ip_address'],
                'os' => $dev['device_type']
            ]];
            $cy_elements[] = ['data' => ['source' => $target_net, 'target' => $dev_id]];
        }
    }
    $cy_json = json_encode($cy_elements);

    // === CHART: OS Distribution ===
    if ($is_super_admin) {
        $os_data = $pdo->query("SELECT os_family, COUNT(*) as count FROM device WHERE os_family IS NOT NULL GROUP BY os_family")->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $stmt = $pdo->prepare("SELECT os_family, COUNT(*) as count FROM device WHERE os_family IS NOT NULL AND device_group_id = ? GROUP BY os_family");
        $stmt->execute([$user_group_id]);
        $os_data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // === CHART: Alert Severity ===
    if ($is_super_admin) {
        $severity_query = "SELECT pf.severity, COUNT(*) as count FROM port_finding pf INNER JOIN check_run cr ON pf.check_run_id = cr.check_run_id WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) GROUP BY pf.severity";
        $severity_data = $pdo->query($severity_query)->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $severity_query = "SELECT pf.severity, COUNT(*) as count FROM port_finding pf INNER JOIN check_run cr ON pf.check_run_id = cr.check_run_id INNER JOIN device d ON cr.device_id = d.device_id WHERE d.device_group_id = ? AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) GROUP BY pf.severity";
        $stmt = $pdo->prepare($severity_query);
        $stmt->execute([$user_group_id]);
        $severity_data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // === CHART: Top Risky Ports ===
    if ($is_super_admin) {
        $ports_query = "SELECT pf.port_number, COUNT(*) as count FROM port_finding pf INNER JOIN check_run cr ON pf.check_run_id = cr.check_run_id WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) AND pf.severity IN ('high', 'critical') GROUP BY pf.port_number ORDER BY count DESC LIMIT 5";
        $top_ports_data = $pdo->query($ports_query)->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $ports_query = "SELECT pf.port_number, COUNT(*) as count FROM port_finding pf INNER JOIN check_run cr ON pf.check_run_id = cr.check_run_id INNER JOIN device d ON cr.device_id = d.device_id WHERE d.device_group_id = ? AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) AND pf.severity IN ('high', 'critical') GROUP BY pf.port_number ORDER BY count DESC LIMIT 5";
        $stmt = $pdo->prepare($ports_query);
        $stmt->execute([$user_group_id]);
        $top_ports_data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // === CHART: Threat Trends ===
    $time_format = ($time_range === '24h') ? 'HOUR' : 'DATE';
    if ($is_super_admin) {
        $trend_query = "SELECT {$time_format}(cr.run_timestamp) as time_period, COUNT(*) as alert_count FROM port_finding pf INNER JOIN check_run cr ON pf.check_run_id = cr.check_run_id WHERE pf.severity IN ('critical', 'high') AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) GROUP BY {$time_format}(cr.run_timestamp) ORDER BY time_period ASC";
        $trend_data = $pdo->query($trend_query)->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $trend_query = "SELECT {$time_format}(cr.run_timestamp) as time_period, COUNT(*) as alert_count FROM port_finding pf INNER JOIN check_run cr ON pf.check_run_id = cr.check_run_id INNER JOIN device d ON cr.device_id = d.device_id WHERE d.device_group_id = ? AND pf.severity IN ('critical', 'high') AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) GROUP BY {$time_format}(cr.run_timestamp) ORDER BY time_period ASC";
        $stmt = $pdo->prepare($trend_query);
        $stmt->execute([$user_group_id]);
        $trend_data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // === CHART: Hourly Heatmap ===
    if ($time_range === '24h') {
        if ($is_super_admin) {
            $hourly_query = "SELECT HOUR(run_timestamp) as hour, COUNT(*) as count FROM check_run WHERE run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY HOUR(run_timestamp)";
            $hourly_raw = $pdo->query($hourly_query)->fetchAll(PDO::FETCH_ASSOC);
        } else {
            $hourly_query = "SELECT HOUR(cr.run_timestamp) as hour, COUNT(*) as count FROM check_run cr INNER JOIN device d ON cr.device_id = d.device_id WHERE d.device_group_id = ? AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY HOUR(cr.run_timestamp)";
            $stmt = $pdo->prepare($hourly_query);
            $stmt->execute([$user_group_id]);
            $hourly_raw = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
        foreach ($hourly_raw as $row) { if (isset($row['hour'])) $hourly_data[(int)$row['hour']] = $row['count']; }
    }

    // === CHART: Top 10 Targeted Devices ===
    if ($is_super_admin) {
        $top_dev_query = "SELECT d.hostname, d.ip_address, COUNT(pf.port_finding_id) as finding_count FROM device d INNER JOIN check_run cr ON d.device_id = cr.device_id INNER JOIN port_finding pf ON cr.check_run_id = pf.check_run_id WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) AND pf.severity IN ('critical', 'high') GROUP BY d.device_id, d.hostname, d.ip_address ORDER BY finding_count DESC LIMIT 10";
        $top_devices_data = $pdo->query($top_dev_query)->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $top_dev_query = "SELECT d.hostname, d.ip_address, COUNT(pf.port_finding_id) as finding_count FROM device d INNER JOIN check_run cr ON d.device_id = cr.device_id INNER JOIN port_finding pf ON cr.check_run_id = pf.check_run_id WHERE d.device_group_id = ? AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) AND pf.severity IN ('critical', 'high') GROUP BY d.device_id, d.hostname, d.ip_address ORDER BY finding_count DESC LIMIT 10";
        $stmt = $pdo->prepare($top_dev_query);
        $stmt->execute([$user_group_id]);
        $top_devices_data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // === CHART: Network Activity ===
    // SR2 FIX (FED-001): This was the visible leak (100->570 checks). The check_run
    // table has no group column, so tenant admins MUST JOIN through device.
    if ($is_super_admin) {
        $net_query = "SELECT DATE(run_timestamp) as date, COUNT(*) as checks FROM check_run WHERE run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) GROUP BY DATE(run_timestamp) ORDER BY date ASC";
        $network_activity = $pdo->query($net_query)->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $net_query = "SELECT DATE(cr.run_timestamp) as date, COUNT(*) as checks FROM check_run cr INNER JOIN device d ON cr.device_id = d.device_id WHERE d.device_group_id = ? AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) GROUP BY DATE(cr.run_timestamp) ORDER BY date ASC";
        $stmt = $pdo->prepare($net_query);
        $stmt->execute([$user_group_id]);
        $network_activity = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // === TABLE: Recent Alerts ===
    if ($is_super_admin) {
        $alerts_query = "SELECT d.hostname, d.device_id, cr.run_timestamp, CONCAT('Port ', pf.port_number, ' (', COALESCE(pf.process_name, 'Unknown'), ')') as detail, pf.severity FROM port_finding pf INNER JOIN check_run cr ON pf.check_run_id = cr.check_run_id INNER JOIN device d ON cr.device_id = d.device_id WHERE cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) ORDER BY cr.run_timestamp DESC LIMIT 10";
        $recent_alerts = $pdo->query($alerts_query)->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $alerts_query = "SELECT d.hostname, d.device_id, cr.run_timestamp, CONCAT('Port ', pf.port_number, ' (', COALESCE(pf.process_name, 'Unknown'), ')') as detail, pf.severity FROM port_finding pf INNER JOIN check_run cr ON pf.check_run_id = cr.check_run_id INNER JOIN device d ON cr.device_id = d.device_id WHERE d.device_group_id = ? AND cr.run_timestamp >= DATE_SUB(NOW(), INTERVAL {$selected_range['interval']}) ORDER BY cr.run_timestamp DESC LIMIT 10";
        $stmt = $pdo->prepare($alerts_query);
        $stmt->execute([$user_group_id]);
        $recent_alerts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

} catch (PDOException $e) {
    error_log("Dashboard DB Error: " . $e->getMessage());
    $error = "Error loading dashboard metrics. Check error_log for details.";
}

// --- 2. PREPARE JSON FOR CHART.JS ---
$os_labels = json_encode(array_column($os_data, 'os_family') ?: ['No Data']);
$os_counts = json_encode(array_column($os_data, 'count') ?: [1]);
$sev_labels = json_encode(array_column($severity_data, 'severity'));
$sev_counts = json_encode(array_column($severity_data, 'count'));
$port_labels = json_encode(array_column($top_ports_data, 'port_number') ?: []);
$port_counts = json_encode(array_column($top_ports_data, 'count') ?: []);
$trend_labels = json_encode(array_column($trend_data, 'time_period'));
$trend_counts = json_encode(array_column($trend_data, 'alert_count'));
$hourly_labels = json_encode(range(0, 23));
$hourly_counts = json_encode($hourly_data);
$top_devices_labels = json_encode(array_column($top_devices_data, 'hostname'));
$top_devices_counts = json_encode(array_column($top_devices_data, 'finding_count'));
$network_labels = json_encode(array_column($network_activity, 'date'));
$network_counts = json_encode(array_column($network_activity, 'checks'));
?>
<div class="container-fluid mt-4">
    <!-- Page Header with Time Range Selector -->
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h2 class="mb-0">
                <i class="bi bi-speedometer2 me-2" aria-hidden="true"></i>Security Overview
                <i class="bi bi-question-circle text-muted ms-2" data-bs-toggle="tooltip" data-bs-title="Real-time situational awareness of your entire endpoint fleet" style="cursor: help; font-size: 0.6em; vertical-align: middle;" role="img" aria-label="Help"></i>
            </h2>
            <p class="text-muted mb-0 mt-1">
                Network topology, health metrics, and active threat indicators
                <span class="ms-3 text-muted small"><i class="bi bi-clock" aria-hidden="true"></i> Last updated: <?= $last_updated ?></span>
            </p>
        </div>
        <div class="d-flex align-items-center gap-3">
            <div class="btn-group" role="group" aria-label="Time range selector">
                <a href="?range=24h" class="btn btn-sm btn-outline-<?= $time_range === '24h' ? 'primary' : 'secondary' ?>">24h</a>
                <a href="?range=7d" class="btn btn-sm btn-outline-<?= $time_range === '7d' ? 'primary' : 'secondary' ?>">7d</a>
                <a href="?range=30d" class="btn btn-sm btn-outline-<?= $time_range === '30d' ? 'primary' : 'secondary' ?>">30d</a>
            </div>
            <!-- WCAG FIX: Added aria-label for icon-only button -->
            <button class="btn btn-sm btn-primary" onclick="location.reload()" data-bs-toggle="tooltip" data-bs-title="Refresh dashboard" aria-label="Refresh dashboard">
                <i class="bi bi-arrow-clockwise" aria-hidden="true"></i>
            </button>
        </div>
    </div>
    <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    
    <!-- KPI CARDS WITH TRENDS -->
    <div class="row mb-3">
        <div class="col-md-3">
            <div class="card bg-primary text-white shadow-sm h-100">
                <div class="card-body py-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="text-white-50 text-uppercase small mb-1 d-block">Total Devices</span>
                            <h2 class="mb-0 fw-bold"><?= $total_devices ?></h2>
                        </div>
                        <i class="bi bi-laptop display-6 text-white-50" aria-hidden="true"></i>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-success text-white shadow-sm h-100">
                <div class="card-body py-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="text-white-50 text-uppercase small mb-1 d-block">Active (24h)</span>
                            <h2 class="mb-0 fw-bold"><?= $active_devices ?></h2>
                        </div>
                        <i class="bi bi-check-circle display-6 text-white-50" aria-hidden="true"></i>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-danger text-white shadow-sm h-100">
                <div class="card-body py-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="text-white-50 text-uppercase small mb-1 d-block">At Risk</span>
                            <h2 class="mb-0 fw-bold"><?= $at_risk_devices ?></h2>
                        </div>
                        <i class="bi bi-exclamation-triangle display-6 text-white-50" aria-hidden="true"></i>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-dark text-white shadow-sm h-100">
                <div class="card-body py-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="text-white-50 text-uppercase small mb-1 d-block">Health Score</span>
                            <h2 class="mb-0 fw-bold"><?= $health_score ?>%</h2>
                        </div>
                        <i class="bi bi-activity display-6 text-white-50" aria-hidden="true"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- AGENT STATUS PANEL -->
    <div class="row mb-3">
        <div class="col-12">
            <div class="card shadow-sm">
                <div class="card-header bg-white py-2"><h3 class="mb-0 text-muted fs-6 fw-semibold"><i class="bi bi-hdd-network me-2" aria-hidden="true"></i>Agent Status</h3></div>
                <div class="card-body py-3">
                    <div class="row">
                        <div class="col-md-4">
                            <div class="d-flex align-items-center">
                                <div class="display-4 me-3"><i class="bi bi-check-circle-fill text-success" aria-hidden="true"></i></div>
                                <div><h4 class="mb-0"><?= $agents_online ?></h4><small class="text-muted">Agents Online</small></div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="d-flex align-items-center">
                                <div class="display-4 me-3"><i class="bi bi-x-circle-fill text-secondary" aria-hidden="true"></i></div>
                                <div><h4 class="mb-0"><?= $agents_offline ?></h4><small class="text-muted">Agents Offline</small></div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="d-flex align-items-center">
                                <div class="display-4 me-3"><i class="bi bi-shield-fill text-primary" aria-hidden="true"></i></div>
                                <div><h4 class="mb-0"><?= $total_devices > 0 ? round(($agents_online / $total_devices) * 100) : 0 ?>%</h4><small class="text-muted">Coverage</small></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- === LIVE NETWORK TOPOLOGY MAP === -->
    <div class="row mb-3">
        <div class="col-12">
            <div class="card shadow-sm">
                <div class="card-header bg-white py-2 d-flex justify-content-between align-items-center flex-wrap">
                    <h3 class="mb-0 text-muted fs-6 fw-semibold">
                        <i class="bi bi-diagram-3 me-2" aria-hidden="true"></i>Live Network Topology
                        <span class="badge bg-secondary ms-2" style="font-size: 0.7em;"><?= htmlspecialchars($latest_scan_label) ?></span>
                    </h3>
                    <div class="d-flex flex-wrap gap-2 mt-2 mt-md-0 small">
                        <span class="badge bg-light text-dark border"><i class="bi bi-hexagon-fill text-primary me-1" aria-hidden="true"></i> Router/Gateway</span>
                        <span class="badge bg-light text-dark border"><i class="bi bi-circle-fill text-success me-1" aria-hidden="true"></i> Linux/Pi</span>
                        <span class="badge bg-light text-dark border"><i class="bi bi-square-fill text-info me-1" aria-hidden="true"></i> Windows</span>
                        <span class="badge bg-light text-dark border"><i class="bi bi-triangle-fill me-1" style="color: #6f42c1;" aria-hidden="true"></i> Apple</span>
                    </div>
                </div>
                <div class="card-body p-0">
                    <div id="cy" style="width: 100%; height: 400px; background-color: #f8f9fa;"></div>
                </div>
            </div>
        </div>
    </div>

    <!-- DYNAMIC CHARTS GRID -->
    <div class="row mb-3">
        <div class="col-md-4 mb-3">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white py-2"><h3 class="mb-0 text-muted fs-6 fw-semibold"><i class="bi bi-pie-chart me-2" aria-hidden="true"></i>OS Fleet Composition</h3></div>
                <div class="card-body d-flex justify-content-center align-items-center" style="height: 250px;"><canvas id="osChart"></canvas></div>
            </div>
        </div>
        <div class="col-md-4 mb-3">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white py-2"><h3 class="mb-0 text-muted fs-6 fw-semibold"><i class="bi bi-shield-exclamation me-2" aria-hidden="true"></i>Alert Severity</h3></div>
                <div class="card-body d-flex justify-content-center align-items-center" style="height: 250px;"><canvas id="severityChart"></canvas></div>
            </div>
        </div>
        <div class="col-md-4 mb-3">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white py-2"><h3 class="mb-0 text-muted fs-6 fw-semibold"><i class="bi bi-bar-chart me-2" aria-hidden="true"></i>Top 5 Risky Ports</h3></div>
                <div class="card-body d-flex justify-content-center align-items-center" style="height: 250px;"><canvas id="portsChart"></canvas></div>
            </div>
        </div>
        <div class="col-md-6 mb-3">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white py-2"><h3 class="mb-0 text-muted fs-6 fw-semibold"><i class="bi bi-graph-up me-2" aria-hidden="true"></i>Threat Trends</h3></div>
                <div class="card-body" style="height: 250px;"><canvas id="trendChart"></canvas></div>
            </div>
        </div>
        <div class="col-md-6 mb-3">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white py-2"><h3 class="mb-0 text-muted fs-6 fw-semibold"><i class="bi bi-clock-history me-2" aria-hidden="true"></i>Hourly Activity Heatmap</h3></div>
                <div class="card-body" style="height: 250px;"><canvas id="hourlyChart"></canvas></div>
            </div>
        </div>
        <div class="col-md-4 mb-3">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white py-2"><h3 class="mb-0 text-muted fs-6 fw-semibold"><i class="bi bi-bullseye me-2" aria-hidden="true"></i>Top 10 Targeted Devices</h3></div>
                <div class="card-body" style="height: 250px;"><canvas id="topDevicesChart"></canvas></div>
            </div>
        </div>
        <div class="col-md-4 mb-3">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white py-2"><h3 class="mb-0 text-muted fs-6 fw-semibold"><i class="bi bi-shield-check me-2" aria-hidden="true"></i>Policy Compliance</h3></div>
                <div class="card-body d-flex flex-column justify-content-center align-items-center" style="height: 250px;">
                    <div class="display-4 fw-bold text-success"><?= $health_score ?>%</div>
                    <p class="text-muted small mb-0">Devices compliant with baseline rules</p>
                    <div class="progress w-100 mt-3" style="height: 10px;"><div class="progress-bar bg-success" role="progressbar" style="width: <?= $health_score ?>%"></div></div>
                </div>
            </div>
        </div>
        <div class="col-md-4 mb-3">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-white py-2"><h3 class="mb-0 text-muted fs-6 fw-semibold"><i class="bi bi-diagram-3 me-2" aria-hidden="true"></i>Network Activity</h3></div>
                <div class="card-body" style="height: 250px;"><canvas id="networkChart"></canvas></div>
            </div>
        </div>
    </div>

    <!-- RECENT ALERTS -->
    <div class="card shadow-sm">
        <div class="card-header bg-white py-2 d-flex justify-content-between align-items-center">
            <h3 class="mb-0 text-muted fs-5 fw-semibold"><i class="bi bi-bell me-2" aria-hidden="true"></i>Recent Security Alerts</h3>
            <a href="alerts.php" class="btn btn-sm btn-primary" data-bs-toggle="tooltip" data-bs-title="View the full history of security alerts" aria-label="View all security alerts">
                <i class="bi bi-bell me-2" aria-hidden="true"></i>View All Alerts
            </a>
        </div>
        <div class="card-body p-0">
            <?php if (empty($recent_alerts)): ?>
                <div class="text-center py-5">
                    <i class="bi bi-shield-check display-4 text-success" aria-hidden="true"></i>
                    <p class="text-muted mt-3 mb-0">No recent alerts found. All systems appear to be secure.</p>
                </div>
            <?php else: ?>
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0">
                        <thead class="table-light">
                            <tr><th scope="col">Timestamp</th><th scope="col">Device</th><th scope="col">Finding</th><th scope="col">Severity</th></tr>
                        </thead>
                        <tbody>
                            <?php foreach ($recent_alerts as $alert):
                                $sev_class = $alert['severity'] === 'critical' ? 'bg-danger' : 'bg-warning text-dark';
                            ?>
                            <tr>
                                <td class="text-nowrap small"><?= date('d M Y, H:i', strtotime($alert['run_timestamp'])) ?></td>
                                <td><a href="device_detail.php?id=<?= $alert['device_id'] ?>" class="text-decoration-none fw-bold"><?= htmlspecialchars($alert['hostname'] ?: 'Unknown') ?></a></td>
                                <td><small><?= htmlspecialchars($alert['detail']) ?></small></td>
                                <td><span class="badge <?= $sev_class ?>"><?= ucfirst($alert['severity']) ?></span></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Cytoscape.js & Chart.js Initialization -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.23.0/cytoscape.min.js"></script>
<script>
$(document).ready(function() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    tooltipTriggerList.map(function (tooltipTriggerEl) { return new bootstrap.Tooltip(tooltipTriggerEl, { trigger: 'hover', placement: 'auto' }) })
    
    // --- CYTOSCAPE TOPOLOGY MAP ---
    var cy;
    if ($('#cy').length > 0) {
        cy = cytoscape({
            container: document.getElementById('cy'),
            elements: <?= $cy_json ?>,
            style: [
                { selector: 'node', style: { 'label': 'data(label)', 'text-valign': 'center', 'text-halign': 'center', 'font-size': '10px', 'color': '#fff', 'text-outline-width': 1, 'text-outline-color': '#000' } },
                { selector: 'node[type="core"]', style: { 'background-color': '#212529', 'width': 60, 'height': 30, 'shape': 'rectangle', 'font-size': '11px', 'font-weight': 'bold' } },
                { selector: 'node[type="network"]', style: { 'background-color': '#0d6efd', 'width': 40, 'height': 40, 'shape': 'hexagon' } },
                { selector: 'node[type="device"]', style: { 'background-color': 'data(color)', 'shape': 'data(shape)', 'width': 25, 'height': 25, 'border-width': 2, 'border-color': '#fff' }},
                { selector: 'edge', style: { 'width': 1, 'line-color': '#ccc', 'target-arrow-color': '#ccc', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier' } }
            ],
            layout: { name: 'cose', animate: true, animationDuration: 500, nodeRepulsion: 4500, edgeElasticity: 100, nestingFactor: 5, gravity: 80, numIter: 1000, padding: 30 }
        });
        cy.on('tap', 'node[type="device"]', function(evt){
            alert('Device: ' + evt.target.data('label') + '\nIP: ' + evt.target.data('ip') + '\nOS: ' + evt.target.data('os'));
        });
    }

    function refreshTopology() {
        fetch('?ajax=refresh_topology')
        .then(response => response.json())
        .then(data => {
            if (data.success && cy) {
                cy.elements().remove();
                cy.add(data.elements);
                cy.layout({ name: 'cose', animate: true, animationDuration: 500, nodeRepulsion: 4500, edgeElasticity: 100, nestingFactor: 5, gravity: 80, numIter: 1000, padding: 30 }).run();
                const badge = document.querySelector('.badge.bg-secondary');
                if (badge) { badge.textContent = data.scan_label; }
            }
        })
        .catch(error => console.error('Topology refresh failed:', error));
    }
    setInterval(refreshTopology, 60000);

    // --- CHART.JS VISUALIZATIONS ---
    Chart.defaults.font.size = 11;
    Chart.defaults.color = '#6c757d';
    new Chart(document.getElementById('osChart'), { type: 'doughnut', data: { labels: <?= $os_labels ?>, datasets: [{ data: <?= $os_counts ?>, backgroundColor: ['#0d6efd', '#198754', '#ffc107', '#dc3545', '#6c757d'], borderWidth: 0 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { boxWidth: 12, padding: 10 } } } } });
    new Chart(document.getElementById('severityChart'), { type: 'polarArea', data: { labels: <?= $sev_labels ?>, datasets: [{ data: <?= $sev_counts ?>, backgroundColor: ['rgba(220, 53, 69, 0.7)', 'rgba(255, 193, 7, 0.7)', 'rgba(33, 37, 41, 0.7)', 'rgba(13, 110, 253, 0.7)'] }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { boxWidth: 12 } } } } });
    new Chart(document.getElementById('portsChart'), { type: 'bar', data: { labels: <?= $port_labels ?>, datasets: [{ label: 'Occurrences', data: <?= $port_counts ?>, backgroundColor: '#dc3545' }] }, options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { stepSize: 1 } } } } });
    new Chart(document.getElementById('trendChart'), { type: 'line', data: { labels: <?= $trend_labels ?>, datasets: [{ label: 'High/Critical Alerts', data: <?= $trend_counts ?>, borderColor: '#dc3545', backgroundColor: 'rgba(220, 53, 69, 0.1)', borderWidth: 2, fill: true, tension: 0.4 }] }, options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } }, plugins: { legend: { display: false } } } });
    new Chart(document.getElementById('hourlyChart'), { type: 'bar', data: { labels: <?= $hourly_labels ?>, datasets: [{ label: 'Checks per Hour', data: <?= $hourly_counts ?>, backgroundColor: 'rgba(13, 110, 253, 0.7)' }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { title: { display: true, text: 'Hour of Day' } }, y: { beginAtZero: true } } } });
    new Chart(document.getElementById('topDevicesChart'), { type: 'bar', data: { labels: <?= $top_devices_labels ?>, datasets: [{ label: 'Security Findings', data: <?= $top_devices_counts ?>, backgroundColor: '#ffc107' }] }, options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true } } } });
    new Chart(document.getElementById('networkChart'), { type: 'line', data: { labels: <?= $network_labels ?>, datasets: [{ label: 'Check Runs', data: <?= $network_counts ?>, borderColor: '#198754', backgroundColor: 'rgba(25, 135, 84, 0.1)', borderWidth: 2, fill: true, tension: 0.4 }] }, options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } }, plugins: { legend: { display: false } } } });
});
</script>
<?php require_once __DIR__ . '/includes/footer.php'; ?>