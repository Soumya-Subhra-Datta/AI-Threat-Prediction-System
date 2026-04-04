import os
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()

class Config:
    # DB
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    DB_NAME = os.getenv('DB_NAME', 'cyber_threat_db')

    # API
    CERBERUS_API_KEY = os.getenv('CERBERUS_API_KEY')
    CERBERUS_API_URL = os.getenv('CERBERUS_API_URL')

    # Flask
    DEBUG = os.getenv('FLASK_DEBUG', 'False') == 'True'
    PORT = int(os.getenv('FLASK_PORT', 5000))