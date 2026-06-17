USE netsentinel;

CREATE TABLE device_group (
    device_group_id INT AUTO_INCREMENT PRIMARY KEY
    , name VARCHAR(100) NOT NULL
    , description TEXT
);

CREATE TABLE device (
    device_id INT AUTO_INCREMENT PRIMARY KEY
    , hostname VARCHAR(255) NOT NULL
    , device_group_id INT
    , os_family VARCHAR(50)
    , os_version VARCHAR(50)
    , first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    , last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    , agent_version VARCHAR(50)
    , current_health_status VARCHAR(50) DEFAULT 'Unknown'
    , FOREIGN KEY (device_group_id) REFERENCES device_group(device_group_id) ON DELETE SET NULL
);

CREATE TABLE baseline_rule (
    baseline_rule_id INT AUTO_INCREMENT PRIMARY KEY
    , rule_type VARCHAR(50) NOT NULL
    , parameter VARCHAR(255) NOT NULL
    , operator VARCHAR(20) NOT NULL
    , threshold_value VARCHAR(255)
    , severity_if_violated VARCHAR(20) DEFAULT 'Medium'
    , device_group_id INT
    , FOREIGN KEY (device_group_id) REFERENCES device_group(device_group_id) ON DELETE CASCADE
);

CREATE TABLE check_run (
    check_run_id INT AUTO_INCREMENT PRIMARY KEY
    , device_id INT NOT NULL
    , run_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    , latency_ms INT
    , overall_status VARCHAR(50)
    , raw_payload_hash VARCHAR(255)
    , FOREIGN KEY (device_id) REFERENCES device(device_id) ON DELETE CASCADE
);

CREATE TABLE port_finding (
    port_finding_id INT AUTO_INCREMENT PRIMARY KEY
    , check_run_id INT NOT NULL
    , port_number INT NOT NULL
    , protocol VARCHAR(10) NOT NULL
    , process_name VARCHAR(255)
    , status VARCHAR(50)
    , is_expected BOOLEAN
    , severity VARCHAR(20)
    , FOREIGN KEY (check_run_id) REFERENCES check_run(check_run_id) ON DELETE CASCADE
);

CREATE TABLE service_finding (
    service_finding_id INT AUTO_INCREMENT PRIMARY KEY
    , check_run_id INT NOT NULL
    , service_name VARCHAR(255) NOT NULL
    , detected_state VARCHAR(50)
    , expected_state VARCHAR(50)
    , severity VARCHAR(20)
    , FOREIGN KEY (check_run_id) REFERENCES check_run(check_run_id) ON DELETE CASCADE
);

CREATE TABLE patch_finding (
    patch_finding_id INT AUTO_INCREMENT PRIMARY KEY
    , check_run_id INT NOT NULL
    , missing_critical_count INT DEFAULT 0
    , missing_important_count INT DEFAULT 0
    , latest_update_count INT DEFAULT 0
    , high_severity_cve_count INT DEFAULT 0
    , FOREIGN KEY (check_run_id) REFERENCES check_run(check_run_id) ON DELETE CASCADE
);

CREATE TABLE firewall_finding (
    firewall_finding_id INT AUTO_INCREMENT PRIMARY KEY
    , check_run_id INT NOT NULL
    , profile VARCHAR(100)
    , enabled BOOLEAN
    , risky_rule_count INT DEFAULT 0
    , status VARCHAR(50)
    , FOREIGN KEY (check_run_id) REFERENCES check_run(check_run_id) ON DELETE CASCADE
);

CREATE TABLE user (
    user_id INT AUTO_INCREMENT PRIMARY KEY
    , username VARCHAR(100) UNIQUE NOT NULL
    , password_hash VARCHAR(255) NOT NULL
    , role ENUM('Admin', 'Viewer') DEFAULT 'Viewer'
    , created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audit_log (
    log_id INT AUTO_INCREMENT PRIMARY KEY
    , user_id INT
    , action VARCHAR(255) NOT NULL
    , details TEXT
    , created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    , FOREIGN KEY (user_id) REFERENCES user(user_id) ON DELETE SET NULL
);
