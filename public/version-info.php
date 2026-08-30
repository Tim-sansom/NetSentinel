<?php
require_once 'includes/version.php';
$info = get_version_info();
?>
<!DOCTYPE html>
<html>
<head><title>Version Info</title></head>
<body>
    <h1>NetSentinel Version Information</h1>
    <p><strong>Current Version:</strong> <?php echo htmlspecialchars($info['version']); ?></p>
    <p><strong>Last Bumped:</strong> <?php echo htmlspecialchars($info['last_bumped']); ?></p>
    <p><strong>Triggered By:</strong> <?php echo htmlspecialchars($info['triggered_by'] ?? 'N/A'); ?></p>
    <pre><?php echo htmlspecialchars(json_encode($info, JSON_PRETTY_PRINT)); ?></pre>
</body>
</html>