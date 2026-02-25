from cryptography.fernet import Fernet
import base64
import os

class CryptoUtils:
    def __init__(self, key=None):
        if key is None:
            # Generate a new key if not provided
            key = Fernet.generate_key()
        self.cipher = Fernet(key)
    
    @staticmethod
    def generate_key():
        """Generate a new encryption key"""
        return Fernet.generate_key()
    
    def encrypt(self, data):
        """Encrypt data"""
        if isinstance(data, str):
            data = data.encode()
        return self.cipher.encrypt(data)
    
    def decrypt(self, encrypted_data):
        """Decrypt data"""
        return self.cipher.decrypt(encrypted_data).decode()
    
    @staticmethod
    def hash_password(password):
        """Hash a password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    @staticmethod
    def verify_password(password, password_hash):
        """Verify a password against its hash"""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash)
