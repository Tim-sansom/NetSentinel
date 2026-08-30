<?php http_response_code(500); ?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>500 - System Malfunction | NetSentinel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="landing-page error-page error-500">
    <div class="ambient-bg"></div>
    <div class="container">
        <div class="error-card">
            <i class="bi bi-cpu error-icon text-warning"></i>
            <div class="error-code">500</div>
            <h2 class="mb-3">System Malfunction</h2>
            <p class="text-secondary mb-4 fs-5">
                The backend API is experiencing a critical failure. 
                Our engineering team has been notified. Please try again shortly.
            </p>
            <div class="d-flex gap-3 justify-content-center flex-wrap">
                <a href="index.php" class="btn btn-primary-glow">
                    <i class="bi bi-house me-2"></i>Return to Base
                </a>
                <button onclick="window.location.reload()" class="btn btn-glass">
                    <i class="bi bi-arrow-clockwise me-2"></i>Retry Connection
                </button>
            </div>
        </div>
    </div>
</body>
</html>