<?php
// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Default page title if not set by the calling page
$page_title = $page_title ?? 'Dashboard'; 
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Auto-refresh every 30 seconds for live updates -->
    <meta http-equiv="refresh" content="30">
    <title><?= htmlspecialchars($page_title) ?> - NetSentinel</title>
    
    <!-- Bootstrap 5.3 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- DataTables CSS -->
    <link href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <!-- Custom CSS -->
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body>

<!-- Navigation Bar -->
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold" href="dashboard.php">🛡️ NetSentinel</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <!-- Only show main nav if logged in -->
            <?php if (isset($_SESSION['user_id'])): ?>
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="dashboard.php">Overview</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="devices.php">Devices</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="alerts.php">Recent Alerts</a>
                    </li>
                </ul>
            <?php endif; ?>
            
            <ul class="navbar-nav ms-auto">
                <?php if (isset($_SESSION['user_id'])): ?>
                    <li class="nav-item">
                        <span class="nav-link text-light">
                            👤 <?= htmlspecialchars($_SESSION['username'] ?? 'Admin') ?> 
                            <span class="badge bg-secondary"><?= htmlspecialchars($_SESSION['role'] ?? 'viewer') ?></span>
                        </span>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link text-danger" href="logout.php">Logout</a>
                    </li>
                <?php else: ?>
                    <li class="nav-item">
                        <a class="nav-link" href="login.php">Login</a>
                    </li>
                <?php endif; ?>
            </ul>
        </div>
    </div>
</nav>

<!-- Main Content Wrapper -->
<main class="container mt-4"></main>