"""
MySQL Database Manager
Production-ready database for cyber threat detection
Auto-creates database and all tables
"""

import mysql.connector
from mysql.connector import Error
from config import Config
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self):
        self.connection = None
    
    def connect(self):
        """Connect to MySQL database"""
        try:
            self.connection = mysql.connector.connect(
                host=Config.DB_HOST,
                port=Config.DB_PORT,
                user=Config.DB_USER,
                password=Config.DB_PASSWORD,
                database=Config.DB_NAME
            )
            if self.connection.is_connected():
                logger.info("✅ MySQL database connected")
        except Error as e:
            logger.error(f"❌ Database connection failed: {e}")
    
    def create_database_and_tables(self):
        """Create database if not exists and all tables"""
        try:
            # Connect without database to create DB if needed
            temp_conn = mysql.connector.connect(
                host=Config.DB_HOST,
                port=Config.DB_PORT,
                user=Config.DB_USER,
                password=Config.DB_PASSWORD
            )
            temp_cursor = temp_conn.cursor()
            temp_cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{Config.DB_NAME}`")
            temp_conn.commit()
            temp_cursor.close()
            temp_conn.close()
            logger.info(f"✅ Database '{Config.DB_NAME}' verified/created")
        except Error as e:
            logger.info(f"Database operation: {e}")
        
        # Reconnect with database
        if self.connection:
            self.connection.close()
        self.connect()
        
        if not self.connection or not self.connection.is_connected():
            raise RuntimeError("Cannot connect to MySQL after DB creation")
        
        cursor = self.connection.cursor()
        
        tables = [
            """
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip VARCHAR(45),
                port INT,
                protocol VARCHAR(10),
                severity VARCHAR(20),
                confidence FLOAT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_file VARCHAR(255)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS prediction_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                threat_id INT,
                predicted_severity VARCHAR(20),
                actual_severity VARCHAR(20),
                model_confidence FLOAT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (threat_id) REFERENCES threat_logs(id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip VARCHAR(45) UNIQUE,
                severity VARCHAR(20),
                block_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                unblock_timestamp DATETIME NULL,
                reason TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INT AUTO_INCREMENT PRIMARY KEY,
                metric_type VARCHAR(50),
                value FLOAT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                description TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS model_performance (
                id INT AUTO_INCREMENT PRIMARY KEY,
                accuracy_val FLOAT,
                precision_val FLOAT,
                recall_val FLOAT,
                f1_score_val FLOAT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        ]
        
        for i, create_sql in enumerate(tables):
            try:
                cursor.execute(create_sql)
                logger.info(f"✅ Table {i+1}/5 created/verified")
            except Error as e:
                logger.error(f"❌ Table {i+1} error: {e}")
        
        self.connection.commit()
        cursor.close()
        logger.info("✅ All database tables ready!")
    
    def log_threat(self, ip, port, protocol, severity, confidence, source_file=''):
        """Log detected threat"""
        if not self.connection or not self.connection.is_connected():
            self.connect()
        cursor = self.connection.cursor()
        cursor.execute("""
            INSERT INTO threat_logs (ip, port, protocol, severity, confidence, source_file)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (ip, port, protocol, severity, confidence, source_file))
        self.connection.commit()
        threat_id = cursor.lastrowid
        cursor.close()
        return threat_id
    
    def block_ip(self, ip, severity, reason=''):
        """Block malicious IP"""
        if not self.connection or not self.connection.is_connected():
            self.connect()
        cursor = self.connection.cursor()
        cursor.execute("""
            INSERT IGNORE INTO blocked_ips (ip, severity, reason)
            VALUES (%s, %s, %s)
        """, (ip, severity, reason))
        self.connection.commit()
        cursor.close()
        logger.info(f"🚫 IP {ip} blocked (severity: {severity})")
    
    def is_ip_blocked(self, ip):
        """Check if IP is blocked"""
        if not self.connection or not self.connection.is_connected():
            self.connect()
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM blocked_ips WHERE ip = %s", (ip,))
        result = cursor.fetchone()
        cursor.close()
        return result is not None
    
    def get_recent_threats(self, limit=50):
        """Get recent threats for dashboard"""
        if not self.connection or not self.connection.is_connected():
            self.connect()
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT ip, severity, confidence, timestamp 
            FROM threat_logs 
            ORDER BY timestamp DESC 
            LIMIT %s
        """, (limit,))
        results = cursor.fetchall()
        cursor.close()
        return results
    
    def get_analytics(self):
        """Get threat analytics for dashboard"""
        if not self.connection or not self.connection.is_connected():
            self.connect()
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM threat_logs 
            WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY severity
        """)
        dist = dict(cursor.fetchall())
        cursor.close()
        
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT DATE(timestamp), COUNT(*) 
            FROM threat_logs 
            WHERE timestamp > DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(timestamp)
            ORDER BY DATE(timestamp)
        """)
        timeline = cursor.fetchall()
        cursor.close()
        
        cursor = self.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM blocked_ips")
        blocked_count = cursor.fetchone()[0]
        cursor.close()
        
        return {
            'threat_dist': dist,
            'timeline': timeline,
            'blocked_ips': blocked_count
        }
    
    def close(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            logger.info("🔌 Database connection closed")
