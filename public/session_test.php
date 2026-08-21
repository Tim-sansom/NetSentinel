<?php
// Force errors to show
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h2>🔍 PHP Session Diagnostic Test</h2>";

// 1. Check if session is already active
if (session_status() === PHP_SESSION_NONE) {
    echo "<p>Starting a new session...</p>";
    session_start();
} else {
    echo "<p>Session was already active.</p>";
}

// 2. Show session ID and save path
echo "<p><strong>Session ID:</strong> " . session_id() . "</p>";
echo "<p><strong>Session Save Path:</strong> " . session_save_path() . "</p>";

// 3. Handle form submission to set a session variable
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['set_session'])) {
    $_SESSION['test_user_id'] = 99;
    $_SESSION['test_role'] = 'admin';
    echo "<p style='color:green; font-weight:bold;'>✅ Session variables SET successfully!</p>";
}

// 4. Display current session contents
echo "<h3>Current Session Data:</h3>";
echo "<pre style='background:#f4f4f4; padding:10px;'>";
print_r($_SESSION);
echo "</pre>";

// 5. Provide a button to set the session
echo '<form method="POST">';
echo '<button type="submit" name="set_session" style="padding:10px 20px; background:blue; color:white; border:none; cursor:pointer;">Set Test Session Variables</button>';
echo '</form>';

echo "<hr><p><a href='networks.php'>Go to Networks Page</a> (to see if it remembers)</p>";
?>