CREATE DATABASE IF NOT EXISTS netwatch;
USE netwatch;


CREATE TABLE devices (
    id INT PRIMARY KEY AUTO_INCREMENT,
    mac VARCHAR(17) UNIQUE NOT NULL,
    ip VARCHAR(45),
    hostname VARCHAR(255),
    vendor VARCHAR(255),
    os_type VARCHAR(50), 
    is_trusted BOOLEAN NOT NULL DEFAULT FALSE, 
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    is_online BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_devices_mac_ip ON devices(mac, ip);

CREATE TABLE device_sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    device_id INT NOT NULL,
    started_at DATETIME NOT NULL,
    ended_at DATETIME,
    duration_seconds INT,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE dns_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    device_id INT NOT NULL,
    timestamp DATETIME NOT NULL,
    domain VARCHAR(255) NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX idx_dns_device_time ON dns_logs(device_id, timestamp);

CREATE TABLE traffic_stats (
    id INT PRIMARY KEY AUTO_INCREMENT,
    device_id INT NOT NULL,
    session_id INT,
    timestamp DATETIME NOT NULL,
    bytes_in BIGINT UNSIGNED NOT NULL DEFAULT 0,
    bytes_out BIGINT UNSIGNED NOT NULL DEFAULT 0,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES device_sessions(id) ON DELETE SET NULL
);

CREATE INDEX index_trafic_timestamp on traffic_stats(timestamp);
CREATE INDEX index_trafic_device on traffic_stats(device_id , timestamp);

CREATE TABLE port_scans (
    id INT PRIMARY KEY AUTO_INCREMENT,
    device_id INT NOT NULL,
    scanned_at DATETIME NOT NULL,
    port INT NOT NULL,
    state VARCHAR(20) NOT NULL,
    service VARCHAR(100),
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE tasks_queue (
    id INT PRIMARY KEY AUTO_INCREMENT,
    device_id INT NOT NULL,
    action VARCHAR(50) NOT NULL, 
    status VARCHAR(20) DEFAULT 'pending', 
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);