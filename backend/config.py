import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'dev-jwt-secret-key')
    
    # Database Configuration
    # Default MySQL configuration - update these values for your MySQL server
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = os.getenv('DB_PORT', '3306')
    DB_NAME = os.getenv('DB_NAME', 'threat_detection')
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'root')
    
    # Construct database URI - supports both MySQL and SQLite
    db_type = os.getenv('DB_TYPE', 'mysql').lower()
    if db_type == 'mysql':
        SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 
            f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
    else:
        SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///threat_detection.db')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    SIMULATION_MODE = os.getenv('SIMULATION_MODE', 'true').lower() == 'true'
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', 'your-encryption-key-here')
    
    # JWT Configuration
    JWT_TOKEN_LOCATION = ['headers']
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
