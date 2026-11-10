<?php
/**
 * NetSentinel - Global Header & Layout Template
 * ================================================================================
 * 
 * PURPOSE:
 * Serves as the centralized layout engine for the NetSentinel dashboard.
 * It handles session initialization, Role-Based Access Control (RBAC) routing,
 * asset loading, and the structural division between public and authenticated views.
 * 
 * ACADEMIC SIGNIFICANCE:
 * This file demonstrates foundational web application security and UX design:
 * 1. Centralized RBAC: Ensures navigation links are strictly gated by user role.
 * 2. Defense-in-Depth: Applies consistent XSS sanitization to all dynamic output.
 * 3. Accessibility (WCAG): Implements skip-links, ARIA attributes, and mobile navigation.
 * 
 * SECURITY BOUNDARIES:
 * - SR2 (Access Control): Case-insensitive role validation prevents casing-based bypasses.
 * - SR3 (XSS Prevention): All session-derived variables are escaped via htmlspecialchars().
 * 
 */

// 1. SECURITY: Start session BEFORE any HTML output to prevent session fixation/hijacking.
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Set default page title if not defined by the including script
$page_title = $page_title ?? 'Dashboard'; 

// ===========================================================================
// RBAC & HELPER VARIABLES
// ===========================================================================
$is_logged_in = isset($_SESSION['user_id']);

// SR2: Case-insensitive role check. 
// Prevents authorization bypasses if the database stores "Admin" instead of "admin".
$current_role = strtolower($_SESSION['role'] ?? '');
$is_super_admin = ($current_role === 'super_admin');
$is_admin = $is_logged_in && ($current_role === 'admin' || $is_super_admin);

// SR3: XSS Prevention. 
// Always sanitize user-controlled session data before rendering to the DOM.
$username = htmlspecialchars($_SESSION['username'] ?? 'User');
$role = htmlspecialchars($_SESSION['role'] ?? 'viewer');

// Detect if we are on a public page (no sidebar/top-header needed)
$current_page = basename($_SERVER['PHP_SELF']);
$public_pages = ['login.php', 'register.php', 'index.php', 'forgot_password.php', 'reset_password.php'];
$is_public_page = in_array($current_page, $public_pages);
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- SR3: Escape page title to prevent XSS via dynamic titles -->
    <title><?= htmlspecialchars($page_title) ?> - NetSentinel</title>
    
    <!-- Core CSS Frameworks & Libraries -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">

    <!-- Core JavaScript Libraries -->
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

    <!-- Favicon & App Icons -->
    <link rel="icon" type="image/svg+xml" href="assets/img/favicon.svg">
    <link rel="alternate icon" type="image/png" href="assets/img/favicon.png">
    <link rel="apple-touch-icon" href="assets/img/favicon.png">

    <!-- Theme Initialization: Prevents FOUC (Flash of Unstyled Content) on page load -->
    <script>
        (function() {
            const savedTheme = localStorage.getItem('netsentinel-theme') || 'light';
            document.documentElement.setAttribute('data-bs-theme', savedTheme);
        })();
    </script>
</head>
<!-- NFR3/NFR4: Apply layout class based on page type. Public pages get simple background, app gets flex layout -->
<body class="<?= $is_public_page ? 'bg-light' : 'app-layout' ?>">

<?php if ($is_public_page): ?>
    <!-- ========================================================================= -->
    <!-- SIMPLE NAVBAR FOR PUBLIC PAGES (Login, Register, Password Reset) -->
    <!-- ========================================================================= -->
    <nav class="navbar navbar-light bg-white shadow-sm mb-4" aria-label="Public Navigation">
        <div class="container">
            <a class="navbar-brand d-flex align-items-center" href="index.php">
                <i class="bi bi-shield-lock text-primary me-2" aria-hidden="true"></i>
                <span class="fw-bold">NetSentinel</span>
            </a>
            <div>
                <?php if ($current_page !== 'login.php'): ?>
                    <a href="login.php" class="btn btn-outline-primary me-2">Login</a>
                <?php endif; ?>
                <?php if ($current_page !== 'register.php'): ?>
                    <a href="register.php" class="btn btn-primary">Register</a>
                <?php endif; ?>
            </div>
        </div>
    </nav>
    <div class="container pb-5"> <!-- Public Content Wrapper -->

<?php else: ?>
    <!-- ========================================================================= -->
    <!-- DASHBOARD LAYOUT FOR LOGGED-IN USERS -->
    <!-- ========================================================================= -->
    
    <!-- NFR4 (Accessibility): Skip link for keyboard/screen-reader users to bypass repetitive navigation -->
    <a href="#main-content" class="visually-hidden-focusable position-absolute top-0 start-0 p-3 bg-primary text-white z-3">
        Skip to main content
    </a>

    <!-- 1. LEFT SIDEBAR (Collapsible Navigation) -->
    <!-- FIX: Added id="mainSidebar" for the mobile toggle JavaScript to target -->
    <nav class="sidebar" id="mainSidebar" aria-label="Main Dashboard Navigation">
        <div class="nav flex-column">
            <!-- Standard Navigation Links -->
            <a class="nav-link <?= $current_page == 'dashboard.php' ? 'active' : '' ?>" href="dashboard.php">
                <i class="bi bi-speedometer2" aria-hidden="true"></i><span>Overview</span>
            </a>
            <a class="nav-link <?= $current_page == 'devices.php' ? 'active' : '' ?>" href="devices.php">
                <i class="bi bi-hdd-network" aria-hidden="true"></i><span>Devices</span>
            </a>
            <a class="nav-link <?= $current_page == 'alerts.php' ? 'active' : '' ?>" href="alerts.php">
                <i class="bi bi-bell" aria-hidden="true"></i><span>Recent Alerts</span>
            </a>
            <a class="nav-link <?= $current_page == 'anomalies.php' ? 'active' : '' ?>" href="anomalies.php">
                <i class="bi bi-exclamation-triangle" aria-hidden="true"></i><span>Log Anomalies</span>
            </a>
            <a class="nav-link <?= $current_page == 'discover.php' ? 'active' : '' ?>" href="discover.php">
                <i class="bi bi-search" aria-hidden="true"></i><span>Discovery</span>
            </a>
            <a class="nav-link <?= $current_page == 'networks.php' ? 'active' : '' ?>" href="networks.php">
                <i class="bi bi-diagram-3" aria-hidden="true"></i><span>Networks</span>
            </a>
            <a class="nav-link <?= $current_page == 'threats.php' ? 'active' : '' ?>" href="threats.php">
                <i class="bi bi-shield-exclamation" aria-hidden="true"></i><span>Threats</span>
            </a>
            <a class="nav-link <?= $current_page == 'help.php' ? 'active' : '' ?>" href="help.php">
                <i class="bi bi-question-circle" aria-hidden="true"></i><span>Help</span>
            </a>
            
            <!-- SR2: Admin-Only Navigation Links -->
            <?php if ($is_admin): ?>
                <hr class="border-secondary mx-3 my-2" role="presentation">
                <a class="nav-link text-warning <?= $current_page == 'admin_users.php' ? 'active' : '' ?>" href="admin_users.php">
                    <i class="bi bi-people-fill" aria-hidden="true"></i><span>User Management</span>
                </a>
                <a class="nav-link text-warning <?= $current_page == 'admin_groups.php' ? 'active' : '' ?>" href="admin_groups.php">
                    <i class="bi bi-shield-check" aria-hidden="true"></i><span>Policy Management</span>
                </a>
                <a class="nav-link text-warning <?= $current_page == 'audit_logs.php' ? 'active' : '' ?>" href="audit_logs.php">
                    <i class="bi bi-journal-text" aria-hidden="true"></i><span>Audit Logs</span>
                </a>
            <?php endif; ?>

            <!-- SR2: Super Admin-Only Navigation Links (Deep Diagnostics) -->
            <?php if ($is_super_admin): ?>
                <hr class="border-secondary mx-3 my-2" role="presentation">
                <!-- FIX: Changed href and active check from server_telemetry.php to server_metrics.php -->
                <a class="nav-link text-info <?= $current_page == 'server_metrics.php' ? 'active' : '' ?>" href="server_metrics.php">
                    <i class="bi bi-activity" aria-hidden="true"></i><span>Server Telemetry</span>
                </a>
                <a class="nav-link text-info <?= $current_page == 'user_audit.php' ? 'active' : '' ?>" href="user_audit.php">
                    <i class="bi bi-shield-lock" aria-hidden="true"></i><span>Session Audit</span>
                </a>
            <?php endif; ?>
        </div>
    </nav>

    <!-- 2. RIGHT-HAND MAIN CONTENT WRAPPER -->
    <div class="main-content">
        <header class="top-header">
            <div class="brand-text">
                <!-- FIX: Added Mobile Hamburger Menu Toggle Button (Visible only on mobile via d-md-none) -->
                <button class="btn btn-link nav-link d-md-none p-0 me-2" id="sidebarToggle" aria-label="Toggle navigation menu" style="color: inherit;">
                    <i class="bi bi-list fs-4"></i>
                </button>
                
                <i class="bi bi-shield-lock me-2 text-info" aria-hidden="true"></i> NetSentinel
            </div>
            
            <div class="d-flex align-items-center gap-3">
                <!-- NFR3: Theme Toggle Button -->
                <button class="btn btn-link nav-link px-2" id="theme-toggle" aria-label="Toggle dark and light mode" title="Toggle Dark/Light Mode">
                    <i class="bi bi-moon-stars-fill" id="theme-icon" aria-hidden="true"></i>
                </button>

                <?php if ($is_logged_in): ?>
                    <!-- Authenticated User Dropdown -->
                    <div class="dropdown">
                        <button class="btn btn-link nav-link dropdown-toggle d-flex align-items-center gap-2 text-decoration-none" 
                                type="button" 
                                id="userDropdown" 
                                data-bs-toggle="dropdown" 
                                aria-expanded="false" 
                                aria-label="User menu">
                            <i class="bi bi-person-circle" aria-hidden="true"></i> 
                            <!-- SR3: Username and role are pre-sanitized at the top of the file -->
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
                    <!-- Fallback for edge cases where session is lost but layout is loaded -->
                    <a class="btn btn-sm btn-outline-primary" href="login.php">Login</a>
                    <a class="btn btn-sm btn-primary ms-2" href="register.php">Register</a>
                <?php endif; ?>
            </div>
        </header>

        <!-- NFR4: Main content landmark for screen readers and skip-link target -->
        <main id="main-content" class="container-fluid p-4">
<?php endif; ?>