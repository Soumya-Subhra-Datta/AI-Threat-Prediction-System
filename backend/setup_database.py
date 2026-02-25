"""
Setup MySQL Database for AI Threat Detection System
Run this script to create the database and tables
"""

import pymysql
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def create_database():
    """Create the MySQL database if it doesn't exist"""
    
    # Get MySQL connection parameters from environment
    db_host = os.getenv('DB_HOST', 'localhost')
    db_port = int(os.getenv('DB_PORT', '3306'))
    db_user = os.getenv('DB_USER', 'root')
    db_password = os.getenv('DB_PASSWORD', 'root')
    db_name = os.getenv('DB_NAME', 'threat_detection')
    
    print("=" * 60)
    print("MySQL Database Setup for AI Threat Detection System")
    print("=" * 60)
    
    print(f"\nConnecting to MySQL server at {db_host}:{db_port}...")
    
    try:
        # Connect to MySQL server (without database name first)
        conn = pymysql.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password
        )
        print("✓ Connected to MySQL server successfully!")
        
        cursor = conn.cursor()
        
        # Create database if it doesn't exist
        print(f"\nCreating database '{db_name}' if it doesn't exist...")
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
        conn.commit()
        print(f"✓ Database '{db_name}' created or already exists!")
        
        cursor.close()
        conn.close()
        
        # Now connect to the created database
        print(f"\nConnecting to database '{db_name}'...")
        conn = pymysql.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database=db_name
        )
        print("✓ Connected to database successfully!")
        
        cursor = conn.cursor()
        
        # Create tables
        print("\nCreating tables...")
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password_hash VARCHAR(200) NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin BOOLEAN DEFAULT FALSE
            )
        """)
        print("✓ Users table created!")
        
        # ThreatEvents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                threat_type VARCHAR(100) NOT NULL,
                severity VARCHAR(20) NOT NULL,
                source_ip VARCHAR(50),
                description TEXT,
                anomaly_score FLOAT,
                status VARCHAR(20) DEFAULT 'active',
                remediation_action VARCHAR(100)
            )
        """)
        print("✓ ThreatEvents table created!")
        
        # BlockedIPs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(50) UNIQUE NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reason VARCHAR(200),
                blocked_until TIMESTAMP NULL,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)
        print("✓ BlockedIPs table created!")
        
        # SystemLogs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                level VARCHAR(20) NOT NULL,
                source VARCHAR(50),
                message TEXT,
                details TEXT
            )
        """)
        print("✓ SystemLogs table created!")
        
        # RemediationActions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS remediation_actions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action_type VARCHAR(50) NOT NULL,
                target VARCHAR(100),
                status VARCHAR(20) NOT NULL,
                details TEXT,
                simulation_mode BOOLEAN DEFAULT TRUE
            )
        """)
        print("✓ RemediationActions table created!")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print("\n" + "=" * 60)
        print("✓ MySQL database setup completed successfully!")
        print("=" * 60)
        print(f"\nDatabase: {db_name}")
        print(f"Host: {db_host}:{db_port}")
        print("\nNext steps:")
        print("1. Run: python generate_keys.py")
        print("2. Run: python -c \"from model.train_autoencoder import train_model; train_model(epochs=10)\"")
        print("3. Run: python app.py")
        print("4. Access: http://localhost:5000")
        
    except pymysql.err.ConnectionRefusedError:
        print("✗ Error: Could not connect to MySQL server")
        print("  Make sure MySQL server is running and credentials are correct")
        return False
    except pymysql.err.OperationalError as e:
        print(f"✗ Error: {e}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    
    return True

if __name__ == '__main__':
    create_database()
