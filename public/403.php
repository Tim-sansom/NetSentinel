<?php http_response_code(403); ?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 - Access Denied | NetSentinel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="landing-page error-page error-403">
    <div class="ambient-bg"></div>
    <div class="container">
        <div class="error-card">
            <i class="bi bi-shield-lock error-icon text-danger"></i>
            <div class="error-code">403</div>
            <h2 class="mb-3">Access Denied</h2>
            <p class="text-secondary mb-4 fs-5">
                Authentication failed. You do not have the required clearance level 
                to access this sector. This incident has been logged.
            </p>
            <div class="d-flex gap-3 justify-content-center flex-wrap">
                <a href="dashboard.php" class="btn btn-primary-glow">
                    <i class="bi bi-speedometer2 me-2"></i>Return to Dashboard
                </a>
                <a href="login.php" class="btn btn-glass">
                    <i class="bi bi-box-arrow-in-right me-2"></i>Switch User
                </a>
            </div>
        </div>
    </div>
</body>
</html>