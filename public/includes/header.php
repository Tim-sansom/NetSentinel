<?php
// 1. SECURITY: Start session BEFORE any HTML output.
// This prevents "headers already sent" errors and ensures session data is secure.
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$page_title = $page_title ?? 'Dashboard'; 

// 2. Helper variables for cleaner template logic and RBAC
$is_logged_in = isset($_SESSION['user_id']);

// SECURITY (SR2): Case-insensitive role check. 
// Prevents authorization bypass if the database stores the role as "Admin" instead of "admin".
$is_admin = $is_logged_in && isset($_SESSION['role']) && strtolower($_SESSION['role']) === 'admin';

// SECURITY (XSS Prevention): Always sanitize user data before outputting to HTML.
$username = htmlspecialchars($_SESSION['username'] ?? 'User');
$role = htmlspecialchars($_SESSION['role'] ?? 'viewer');
?>
<!DOCTYPE html>
<!-- Added data-bs-theme="light" as default. JS will override this if user prefers dark -->
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
    <!-- Primary Favicon (SVG - Scales perfectly, transparent background) -->
    <link rel="icon" type="image/svg+xml" href="assets/img/favicon.svg">
    
    <!-- Fallback for older browsers -->
    <link rel="alternate icon" type="image/png" href="assets/img/favicon.png">
    
    <!-- Apple Touch Icon (For mobile home screens) -->
    <link rel="apple-touch-icon" href="assets/img/favicon.png">

    <!-- Dark/Light Mode: Prevent Flash of Unstyled Content (FOUC) -->
    <script>
        (function() {
            const savedTheme = localStorage.getItem('netsentinel-theme') || 'light';
            document.documentElement.setAttribute('data-bs-theme', savedTheme);
        })();
    </script>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold" href="<?= $is_logged_in ? 'dashboard.php' : 'index.php' ?>">
            <i class="bi bi-shield-lock"></i> NetSentinel
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            
            <!-- Main Navigation (Left) -->
            <?php if ($is_logged_in): ?>
                <ul class="navbar-nav me-auto">
                    <li class="nav-item"><a class="nav-link" href="dashboard.php"><i class="bi bi-speedometer2"></i> Overview</a></li>
                    <li class="nav-item"><a class="nav-link" href="devices.php"><i class="bi bi-hdd-network"></i> Devices</a></li>
                    <li class="nav-item"><a class="nav-link" href="alerts.php"><i class="bi bi-bell"></i> Recent Alerts</a></li>
                    
                    <!-- Stretch Goal Links -->
                    <li class="nav-item"><a class="nav-link" href="anomalies.php"><i class="bi bi-exclamation-triangle"></i> Log Anomalies</a></li>
                    <li class="nav-item"><a class="nav-link" href="discover.php"><i class="bi bi-search"></i> Discovery</a></li>
                    <li class="nav-item"><a class="nav-link" href="networks.php"><i class="bi bi-diagram-3"></i> Networks</a></li>
                    <li class="nav-item"><a class="nav-link" href="threats.php"><i class="bi bi-shield-exclamation"></i> Threats</a></li>
                    
                    <!-- Help Link (All Users) -->
                    <li class="nav-item"><a class="nav-link" href="help.php"><i class="bi bi-question-circle"></i> Help</a></li>
                    
                    <!-- Admin Only Links (RBAC Enforced) -->
                    <?php if ($is_admin): ?>
                        <li class="nav-item">
                            <a class="nav-link text-warning fw-bold" href="admin_users.php">
                                <i class="bi bi-people-fill"></i> User Management
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link text-warning fw-bold" href="admin_groups.php">
                                <i class="bi bi-shield-check"></i> Policy Management
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link text-warning fw-bold" href="audit_logs.php">
                                <i class="bi bi-journal-text"></i> Audit Logs
                            </a>
                        </li>
                    <?php endif; ?>
                </ul>
            <?php endif; ?>
            
            <!-- User / Auth Navigation (Right) -->
            <ul class="navbar-nav ms-auto align-items-center">
                
                <!-- Dark/Light Mode Toggle Button -->
                <li class="nav-item me-2">
                    <button class="btn btn-link nav-link px-2" id="theme-toggle" title="Toggle Dark/Light Mode">
                        <i class="bi bi-moon-stars-fill" id="theme-icon"></i>
                    </button>
                </li>

                <?php if ($is_logged_in): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle d-flex align-items-center gap-2" href="#" id="userDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="bi bi-person-circle"></i> 
                            <span><?= $username ?></span>
                            <span class="badge bg-secondary"><?= $role ?></span>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="profile.php"><i class="bi bi-gear"></i> My Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item text-danger" href="logout.php"><i class="bi bi-box-arrow-right"></i> Logout</a></li>
                        </ul>
                    </li>
                <?php else: ?>
                    <li class="nav-item"><a class="nav-link" href="login.php"><i class="bi bi-box-arrow-in-right"></i> Login</a></li>
                    <li class="nav-item"><a class="nav-link" href="register.php"><i class="bi bi-person-plus"></i> Register</a></li>
                <?php endif; ?>
            </ul>
        </div>
    </div>
</nav>

<!-- Dark/Light Mode Toggle Logic -->
<script>
    document.addEventListener('DOMContentLoaded', function() {
        const themeToggleBtn = document.getElementById('theme-toggle');
        const themeIcon = document.getElementById('theme-icon');
        
        function updateIcon(theme) {
            if (theme === 'dark') {
                themeIcon.classList.remove('bi-moon-stars-fill');
                themeIcon.classList.add('bi-sun-fill');
            } else {
                themeIcon.classList.remove('bi-sun-fill');
                themeIcon.classList.add('bi-moon-stars-fill');
            }
        }

        // Initialize icon based on current theme
        const currentTheme = document.documentElement.getAttribute('data-bs-theme');
        updateIcon(currentTheme);

        // Toggle logic
themeToggleBtn.addEventListener('click', function() {
    // Read the current theme from the DOM (not the stale variable)
    const currentTheme = document.documentElement.getAttribute('data-bs-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    // Apply the new theme
    document.documentElement.setAttribute('data-bs-theme', newTheme);
    localStorage.setItem('netsentinel-theme', newTheme);
    updateIcon(newTheme);
});
    });
</script>

<main class="container mt-4">