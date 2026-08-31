<?php
// 1. SECURITY: Start session BEFORE any HTML output.
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$page_title = $page_title ?? 'Dashboard'; 

// 2. Helper variables for cleaner template logic and RBAC
$is_logged_in = isset($_SESSION['user_id']);

// SECURITY (SR2): Case-insensitive role check. 
$is_admin = $is_logged_in && isset($_SESSION['role']) && strtolower($_SESSION['role']) === 'admin';

// SECURITY (XSS Prevention): Always sanitize user data before outputting to HTML.
$username = htmlspecialchars($_SESSION['username'] ?? 'User');
$role = htmlspecialchars($_SESSION['role'] ?? 'viewer');
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($page_title) ?> - NetSentinel</title>
    
    <!-- CSS: Bootstrap 5, DataTables, Bootstrap Icons, Custom Styles -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">

    <!-- JS libraries in <head> so page-level inline scripts can use them immediately -->
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

    <!-- Favicons -->
    <link rel="icon" type="image/svg+xml" href="assets/img/favicon.svg">
    <link rel="alternate icon" type="image/png" href="assets/img/favicon.png">
    <link rel="apple-touch-icon" href="assets/img/favicon.png">

    <!-- Dark/Light Mode: Prevent Flash of Unstyled Content (FOUC) -->
    <script>
        (function() {
            const savedTheme = localStorage.getItem('netsentinel-theme') || 'light';
            document.documentElement.setAttribute('data-bs-theme', savedTheme);
        })();
    </script>
</head>
<body class="app-layout">

    <!-- WCAG: Skip to main content link for keyboard/screen reader users -->
    <a href="#main-content" class="visually-hidden-focusable position-absolute top-0 start-0 p-3 bg-primary text-white z-3">Skip to main content</a>

    <!-- 1. LEFT SIDEBAR (Collapsible) -->
    <nav class="sidebar" aria-label="Main Navigation">
        <div class="nav flex-column">
            <a class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'dashboard.php' ? 'active' : '' ?>" href="dashboard.php">
                <i class="bi bi-speedometer2" aria-hidden="true"></i><span>Overview</span>
            </a>
            <a class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'devices.php' ? 'active' : '' ?>" href="devices.php">
                <i class="bi bi-hdd-network" aria-hidden="true"></i><span>Devices</span>
            </a>
            <a class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'alerts.php' ? 'active' : '' ?>" href="alerts.php">
                <i class="bi bi-bell" aria-hidden="true"></i><span>Recent Alerts</span>
            </a>
            <a class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'anomalies.php' ? 'active' : '' ?>" href="anomalies.php">
                <i class="bi bi-exclamation-triangle" aria-hidden="true"></i><span>Log Anomalies</span>
            </a>
            <a class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'discover.php' ? 'active' : '' ?>" href="discover.php">
                <i class="bi bi-search" aria-hidden="true"></i><span>Discovery</span>
            </a>
            <a class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'networks.php' ? 'active' : '' ?>" href="networks.php">
                <i class="bi bi-diagram-3" aria-hidden="true"></i><span>Networks</span>
            </a>
            <a class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'threats.php' ? 'active' : '' ?>" href="threats.php">
                <i class="bi bi-shield-exclamation" aria-hidden="true"></i><span>Threats</span>
            </a>
            <a class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'help.php' ? 'active' : '' ?>" href="help.php">
                <i class="bi bi-question-circle" aria-hidden="true"></i><span>Help</span>
            </a>
            
            <?php if ($is_admin): ?>
                <hr class="border-secondary mx-3 my-2" role="presentation">
                <a class="nav-link text-warning <?= basename($_SERVER['PHP_SELF']) == 'admin_users.php' ? 'active' : '' ?>" href="admin_users.php">
                    <i class="bi bi-people-fill" aria-hidden="true"></i><span>User Management</span>
                </a>
                <a class="nav-link text-warning <?= basename($_SERVER['PHP_SELF']) == 'admin_groups.php' ? 'active' : '' ?>" href="admin_groups.php">
                    <i class="bi bi-shield-check" aria-hidden="true"></i><span>Policy Management</span>
                </a>
                <a class="nav-link text-warning <?= basename($_SERVER['PHP_SELF']) == 'audit_logs.php' ? 'active' : '' ?>" href="audit_logs.php">
                    <i class="bi bi-journal-text" aria-hidden="true"></i><span>Audit Logs</span>
                </a>
            <?php endif; ?>
        </div>
    </nav>

    <!-- 2. RIGHT-HAND MAIN CONTENT -->
    <div class="main-content">
        
        <!-- Minimal Top Header -->
        <header class="top-header">
            <div class="brand-text">
                <i class="bi bi-shield-lock me-2 text-info" aria-hidden="true"></i> NetSentinel
            </div>
            
            <div class="d-flex align-items-center gap-3">
                <!-- Theme Toggle (WCAG: Added aria-label) -->
                <button class="btn btn-link nav-link px-2" id="theme-toggle" aria-label="Toggle dark and light mode" title="Toggle Dark/Light Mode">
                    <i class="bi bi-moon-stars-fill" id="theme-icon" aria-hidden="true"></i>
                </button>

                <?php if ($is_logged_in): ?>
                    <div class="dropdown">
                        <!-- WCAG: Changed <a> to <button> for dropdown triggers, added aria-label -->
                        <button class="btn btn-link nav-link dropdown-toggle d-flex align-items-center gap-2 text-decoration-none" type="button" id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false" aria-label="User menu">
                            <i class="bi bi-person-circle" aria-hidden="true"></i> 
                            <span class="d-none d-md-inline"><?= $username ?></span>
                            <span class="badge bg-secondary"><?= $role ?></span>
                        </button>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="profile.php"><i class="bi bi-gear" aria-hidden="true"></i> My Profile</a></li>
                            <li><hr class="dropdown-divider" role="presentation"></li>
                            <li><a class="dropdown-item text-danger" href="logout.php"><i class="bi bi-box-arrow-right" aria-hidden="true"></i> Logout</a></li>
                        </ul>
                    </div>
                <?php else: ?>
                    <a class="btn btn-sm btn-outline-primary" href="login.php">Login</a>
                    <a class="btn btn-sm btn-primary ms-2" href="register.php">Register</a>
                <?php endif; ?>
            </div>
        </header>

        <!-- Page Content Wrapper (Right-Hand Frame) -->
        <!-- WCAG: Added id="main-content" for the skip link, and fixed the broken </main></main> -->
        <main id="main-content" class="container-fluid p-4">