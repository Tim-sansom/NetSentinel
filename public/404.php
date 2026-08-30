<?php http_response_code(404); ?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Sector Not Found | NetSentinel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="landing-page error-page error-404">
    <div class="ambient-bg"></div>
    <div class="container">
        <div class="error-card">
            <i class="bi bi-compass error-icon text-info"></i>
            <div class="error-code">404</div>
            <h2 class="mb-3">Sector Not Found</h2>
            <p class="text-secondary mb-4 fs-5">
                The endpoint you are looking for does not exist on this network. 
                It may have been moved, deleted, or never existed.
            </p>
            <div class="d-flex gap-3 justify-content-center flex-wrap">
                <a href="index.php" class="btn btn-primary-glow">
                    <i class="bi bi-house me-2"></i>Return to Base
                </a>
                <a href="dashboard.php" class="btn btn-glass">
                    <i class="bi bi-speedometer2 me-2"></i>Dashboard
                </a>
            </div>
        </div>
    </div>
</body>
</html>