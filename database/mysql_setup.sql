-- Create Database
CREATE DATABASE IF NOT EXISTS cyber_threat_db;
USE cyber_threat_db;

-- Table for logging all incoming traffic and the action taken
CREATE TABLE IF NOT EXISTS traffic_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) NOT NULL,
    traffic_data TEXT,
    threat_level VARCHAR(20) NOT NULL,
    action_taken VARCHAR(100)
);

-- Table for tracking exclusively blocked IP addresses
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    blocked_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'Blocked'
);

-- Table for tracking successfully remediated threats
CREATE TABLE IF NOT EXISTS redeemed_threats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    redeemed_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    threat_level VARCHAR(20) NOT NULL
);

-- Note: The Python Flask backend (app.py) includes a function `init_db()`
-- that will execute these exact queries automatically if the database
-- does not exist, providing true zero-touch automation.