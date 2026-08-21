-- NetSentinel Database Schema
-- Designed for SME endpoint security monitoring
-- MySQL 8.0+ compatible

SET NAMES utf8mb4;
SET CHARACTER SET utf8mb4;

-- Drop tables in reverse dependency order (for clean re-runs)
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS finding;
DROP TABLE IF EXISTS check_run;
DROP TABLE IF EXISTS device;
DROP TABLE IF EXISTS network;
DROP TABLE IF EXISTS discovered_device;
DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS vulnerability_feed;
DROP TABLE IF EXISTS cve_watchlist;

-- ============================================
-- USER MANAGEMENT
-- ============================================
CREATE TABLE user (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    role ENUM('admin', 'viewer') NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    
    INDEX idx_username (username),
    INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- NETWORK CONFIGURATION (for discovery scans)
-- ============================================
CREATE TABLE network (
    network_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    cidr VARCHAR(20) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_cidr (cidr)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- DISCOVERED DEVICES (temporary scan results)
-- ============================================
CREATE TABLE discovered_device (
    discovery_id INT AUTO_INCREMENT PRIMARY KEY,
    network_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(20),
    hostname VARCHAR(100),
    is_registered BOOLEAN DEFAULT FALSE,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (network_id) REFERENCES network(network_id) ON DELETE CASCADE,
    INDEX idx_ip (ip_address),
    INDEX idx_network (network_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- DEVICES (registered endpoints)
-- ============================================
CREATE TABLE device (
    device_id VARCHAR(36) PRIMARY KEY COMMENT 'UUID for privacy',
    hostname VARCHAR(100) NOT NULL,
    os_type ENUM('windows', 'linux', 'macos', 'unknown') NOT NULL DEFAULT 'unknown',
    os_version VARCHAR(50),
    ip_address VARCHAR(45),
    mac_address VARCHAR(20),
    agent_version VARCHAR(20),
    is_active BOOLEAN DEFAULT TRUE,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_hostname (hostname),
    INDEX idx_os_type (os_type),
    INDEX idx_last_seen (last_seen),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- CHECK RUNS (each agent execution)
-- ============================================
CREATE TABLE check_run (
    check_run_id VARCHAR(36) PRIMARY KEY COMMENT 'UUID for uniqueness',
    device_id VARCHAR(36) NOT NULL,
    check_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    duration_ms INT COMMENT 'Check execution time in milliseconds',
    status ENUM('success', 'partial', 'failed') NOT NULL DEFAULT 'success',
    error_message TEXT,
    
    FOREIGN KEY (device_id) REFERENCES device(device_id) ON DELETE CASCADE,
    INDEX idx_device (device_id),
    INDEX idx_timestamp (check_timestamp),
    INDEX idx_status (status),
    
    -- Prevent duplicate check runs for same device at same second
    UNIQUE KEY uk_device_timestamp (device_id, check_timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- FINDINGS (security issues detected)
-- ============================================
CREATE TABLE finding (
    finding_id INT AUTO_INCREMENT PRIMARY KEY,
    check_run_id VARCHAR(36) NOT NULL,
    device_id VARCHAR(36) NOT NULL,
    category ENUM('port', 'firewall', 'latency', 'system', 'vulnerability', 'log_anomaly') NOT NULL,
    severity ENUM('critical', 'high', 'medium', 'low', 'info') NOT NULL DEFAULT 'info',
    title VARCHAR(200) NOT NULL,
    details TEXT,
    recommendation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (check_run_id) REFERENCES check_run(check_run_id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES device(device_id) ON DELETE CASCADE,
    INDEX idx_check_run (check_run_id),
    INDEX idx_device (device_id),
    INDEX idx_category (category),
    INDEX idx_severity (severity),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- AUDIT LOG (security trail)
-- ============================================
CREATE TABLE audit_log (
    audit_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(50),
    target_id VARCHAR(100),
    details TEXT,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES user(user_id) ON DELETE SET NULL,
    INDEX idx_user (user_id),
    INDEX idx_action (action),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- VULNERABILITY FEED (CISA KEV data)
-- ============================================
CREATE TABLE vulnerability_feed (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    title TEXT NOT NULL,
    vendor VARCHAR(100),
    product VARCHAR(100),
    severity ENUM('Critical', 'High', 'Medium', 'Low') DEFAULT 'High',
    is_rce BOOLEAN DEFAULT FALSE,
    is_kev BOOLEAN DEFAULT TRUE,
    ransomware_linked BOOLEAN DEFAULT FALSE,
    date_added DATE NOT NULL,
    due_date DATE,
    published_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE KEY uk_cve_id (cve_id),
    INDEX idx_date_added (date_added),
    INDEX idx_is_rce (is_rce),
    INDEX idx_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- CVE WATCHLIST (curated high-risk CVEs)
-- ============================================
CREATE TABLE cve_watchlist (
    cve_id VARCHAR(20) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    severity ENUM('Critical', 'High') DEFAULT 'Critical',
    affected_product VARCHAR(100) NOT NULL,
    vulnerable_versions TEXT NOT NULL,
    is_kev BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_severity (severity),
    INDEX idx_product (affected_product)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- SEED DATA (default admin user)
-- ============================================
-- Password: admin123 (hashed with bcrypt)
INSERT INTO user (username, password_hash, email, role) VALUES
('admin', '$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'admin@netsentinel.local', 'admin');

-- ============================================
-- VIEWS (for dashboard queries)
-- ============================================

-- Latest device status view
CREATE OR REPLACE VIEW v_device_latest AS
SELECT 
    d.device_id,
    d.hostname,
    d.os_type,
    d.os_version,
    d.ip_address,
    d.last_seen,
    d.is_active,
    cr.check_run_id AS latest_check_id,
    cr.check_timestamp AS latest_check_time,
    cr.status AS latest_status,
    COUNT(f.finding_id) AS finding_count,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
    SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high_count
FROM device d
LEFT JOIN check_run cr ON d.device_id = cr.device_id
LEFT JOIN finding f ON cr.check_run_id = f.check_run_id
GROUP BY d.device_id, cr.check_run_id
ORDER BY cr.check_timestamp DESC;

-- Recent findings view
CREATE OR REPLACE VIEW v_recent_findings AS
SELECT 
    f.finding_id,
    f.category,
    f.severity,
    f.title,
    f.details,
    f.created_at,
    d.hostname,
    d.os_type,
    cr.check_timestamp
FROM finding f
JOIN device d ON f.device_id = d.device_id
JOIN check_run cr ON f.check_run_id = cr.check_run_id
ORDER BY f.created_at DESC
LIMIT 100;