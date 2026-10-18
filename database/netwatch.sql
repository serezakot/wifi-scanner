USE netwatch;

CREATE TABLE IF NOT EXISTS devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mac VARCHAR(17) UNIQUE NOT NULL,
    ip VARCHAR(15) DEFAULT NULL,
    vendor VARCHAR(255) DEFAULT NULL,
    os_type VARCHAR(100) DEFAULT NULL,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    is_online BOOLEAN DEFAULT FALSE,
    is_blocked BOOLEAN DEFAULT FALSE,
    is_monitored BOOLEAN DEFAULT TRUE
);

-- 2. Сессии устройств (для привязки статистики и логов к конкретному подключению)
CREATE TABLE IF NOT EXISTS device_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    started_at DATETIME NOT NULL,
    ended_at DATETIME DEFAULT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

-- 3. Логи посещенных сайтов (DNS / HTTPS SNI)
CREATE TABLE IF NOT EXISTS dns_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    session_id INT NOT NULL,
    timestamp DATETIME NOT NULL,
    domain VARCHAR(255) NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES device_sessions(id) ON DELETE CASCADE
);

-- 4. Статистика трафика (байты входящие / исходящие)
CREATE TABLE IF NOT EXISTS traffic_stats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    session_id INT NOT NULL,
    timestamp DATETIME NOT NULL,
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES device_sessions(id) ON DELETE CASCADE
);