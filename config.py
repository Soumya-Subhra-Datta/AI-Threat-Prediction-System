"""
Configuration Management
Handles environment variables and system settings
"""

import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
load_dotenv()

class Config:
    """Central configuration class"""
    
    # Database
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = int(os.getenv('DB_PORT', 3306))
    DB_NAME = os.getenv('DB_NAME', 'threat_detection_db')
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    
    # Flask
    FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')
    FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))
    FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    
    # Model
    MODEL_PATH = os.getenv('MODEL_PATH', 'models/threat_detection_model.h5')
    SCALER_PATH = os.getenv('SCALER_PATH', 'models/scaler.pkl')
    ENCODER_PATH = os.getenv('ENCODER_PATH', 'models/label_encoder.pkl')
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    @classmethod
    def test_connection(cls):
        """Test all configurations"""
        print("🔧 Configuration loaded:")
        print(f"   Database: {cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}")
        print(f"   Flask: {cls.FLASK_HOST}:{cls.FLASK_PORT}")
        print(f"   Model: {cls.MODEL_PATH}")
        return True
