import logging
import os
from datetime import datetime
from database.models import SystemLog
from database.db import db

# Configure logging
def setup_logger(name='threat_detection'):
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # File handler
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        file_handler = logging.FileHandler(
            f'logs/threat_detection_{datetime.now().strftime("%Y%m%d")}.log'
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)
        
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        logger.setLevel(logging.DEBUG)
    
    return logger

def log_to_database(level, source, message, details=None):
    """Log to both file and database"""
    logger = setup_logger()
    
    # Log to file
    if level == 'INFO':
        logger.info(f"[{source}] {message}")
    elif level == 'WARNING':
        logger.warning(f"[{source}] {message}")
    elif level == 'ERROR':
        logger.error(f"[{source}] {message}")
    elif level == 'DEBUG':
        logger.debug(f"[{source}] {message}")
    
    # Log to database
    try:
        log_entry = SystemLog(
            level=level,
            source=source,
            message=message,
            details=details
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log to database: {str(e)}")

# Create logger instance
logger = setup_logger()
