USE netsentinel;

-- ============================================
-- 1. USER & AUDIT MANAGEMENT
-- ============================================
CREATE TABLE IF NOT EXISTS user (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('Admin', 'Viewer') DEFAULT 'Viewer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(255) NOT NULL,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(user_id) ON DELETE SET NULL
);

-- ============================================
-- 2. NETWORK DISCOVERY (New)
-- ============================================
CREATE TABLE IF NOT EXISTS network (
    network_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    cidr VARCHAR(20) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS discovered_device (
    discovery_id INT AUTO_INCREMENT PRIMARY KEY,
    network_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(20),
    hostname VARCHAR(100),
    is_registered BOOLEAN DEFAULT FALSE,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (network_id) REFERENCES network(network_id) ON DELETE CASCADE
);

-- ============================================
-- 3. DEVICES & GROUPS
-- ============================================
CREATE TABLE IF NOT EXISTS device_group (
    device_group_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS device (
    device_id INT AUTO_INCREMENT PRIMARY KEY,
    uuid VARCHAR(36) UNIQUE COMMENT 'Used by Python agent for secure identification',
    hostname VARCHAR(255) NOT NULL,
    device_group_id INT,
    os_family VARCHAR(50),
    os_version VARCHAR(50),
    ip_address VARCHAR(45),
    mac_address VARCHAR(20),
    first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    agent_version VARCHAR(50),
    current_health_status VARCHAR(50) DEFAULT 'Unknown',
    FOREIGN KEY (device_group_id) REFERENCES device_group(device_group_id) ON DELETE SET NULL,
    INDEX idx_uuid (uuid),
    INDEX idx_hostname (hostname)
);

CREATE TABLE IF NOT EXISTS baseline_rule (
    baseline_rule_id INT AUTO_INCREMENT PRIMARY KEY,
    rule_type VARCHAR(50) NOT NULL,
    parameter VARCHAR(255) NOT NULL,
    operator VARCHAR(20) NOT NULL,
    threshold_value VARCHAR(255),
    severity_if_violated VARCHAR(20) DEFAULT 'Medium',
    device_group_id INT,
    FOREIGN KEY (device_group_id) REFERENCES device_group(device_group_id) ON DELETE CASCADE
);

-- ============================================
-- 4. CHECK RUNS & FINDINGS
-- ============================================
CREATE TABLE IF NOT EXISTS check_run (
    check_run_id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    run_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    latency_ms INT,
    overall_status VARCHAR(50),
    raw_payload_hash VARCHAR(255),
    FOREIGN KEY (device_id) REFERENCES device(device_id) ON DELETE CASCADE,
    INDEX idx_device (device_id)
);

-- Port Findings
CREATE TABLE IF NOT EXISTS port_finding (
    port_finding_id INT AUTO_INCREMENT PRIMARY KEY,
    check_run_id INT NOT NULL,
    port_number INT NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    process_name VARCHAR(255),
    status VARCHAR(50),
    is_expected BOOLEAN,
    severity VARCHAR(20),
    FOREIGN KEY (check_run_id) REFERENCES check_run(check_run_id) ON DELETE CASCADE
);

-- Service Findings
CREATE TABLE IF NOT EXISTS service_finding (
    service_finding_id INT AUTO_INCREMENT PRIMARY KEY,
    check_run_id INT NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    detected_state VARCHAR(50),
    expected_state VARCHAR(50),
    severity VARCHAR(20),
    FOREIGN KEY (check_run_id) REFERENCES check_run(check_run_id) ON DELETE CASCADE
);

-- Patch Findings
CREATE TABLE IF NOT EXISTS patch_finding (
    patch_finding_id INT AUTO_INCREMENT PRIMARY KEY,
    check_run_id INT NOT NULL,
    missing_critical_count INT DEFAULT 0,
    missing_important_count INT DEFAULT 0,
    latest_update_count INT DEFAULT 0,
    high_severity_cve_count INT DEFAULT 0,
    FOREIGN KEY (check_run_id) REFERENCES check_run(check_run_id) ON DELETE CASCADE
);

-- Firewall Findings
CREATE TABLE IF NOT EXISTS firewall_finding (
    firewall_finding_id INT AUTO_INCREMENT PRIMARY KEY,
    check_run_id INT NOT NULL,
    profile VARCHAR(100),
    enabled BOOLEAN,
    risky_rule_count INT DEFAULT 0,
    status VARCHAR(50),
    FOREIGN KEY (check_run_id) REFERENCES check_run(check_run_id) ON DELETE CASCADE
);

-- Log Anomaly Findings (New for Log Checks)
CREATE TABLE IF NOT EXISTS log_finding (
    log_finding_id INT AUTO_INCREMENT PRIMARY KEY,
    check_run_id INT NOT NULL,
    log_source VARCHAR(100) COMMENT 'e.g., auth.log, Security Event Log',
    anomaly_type VARCHAR(100) COMMENT 'e.g., brute_force, priv_escalation',
    event_count INT DEFAULT 0,
    severity VARCHAR(20),
    details TEXT,
    FOREIGN KEY (check_run_id) REFERENCES check_run(check_run_id) ON DELETE CASCADE
);

-- ============================================
-- 5. THREAT INTELLIGENCE (New)
-- ============================================
CREATE TABLE IF NOT EXISTS vulnerability_feed (
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
    UNIQUE KEY uk_cve_id (cve_id)
);

CREATE TABLE IF NOT EXISTS cve_watchlist (
    cve_id VARCHAR(20) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    severity ENUM('Critical', 'High') DEFAULT 'Critical',
    affected_product VARCHAR(100) NOT NULL,
    vulnerable_versions TEXT NOT NULL,
    is_kev BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);