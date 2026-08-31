<?php
/**
 * NetSentinel SMTP Configuration
 * WARNING: Do not commit this file with real credentials to public repositories!
 * Add this file to your .gitignore
 */

// Example: Using Gmail (Recommended for easy setup)
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587);
define('SMTP_USERNAME', 'your-email@gmail.com');       // REPLACE with your email
define('SMTP_PASSWORD', 'your-16-character-app-pass'); // REPLACE with Gmail App Password
define('SMTP_FROM_EMAIL', 'your-email@gmail.com');
define('SMTP_FROM_NAME', 'NetSentinel Security');
define('SMTP_ENCRYPTION', 'tls'); // Use 'tls' for port 587, or 'ssl' for port 465