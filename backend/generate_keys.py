"""
Generate secure keys for the application
Run this script to generate new SECRET_KEY and JWT_SECRET_KEY values
"""

import secrets
import string

def generate_secure_key(length=50):
    """Generate a secure random key"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_fernet_key():
    """Generate a Fernet encryption key"""
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode()

if __name__ == '__main__':
    print("=" * 60)
    print("Secure Key Generator for AI Threat Detection System")
    print("=" * 60)
    
    # Generate keys
    secret_key = generate_secure_key(50)
    jwt_secret_key = generate_secure_key(50)
    
    print("\nGenerated Keys:")
    print("-" * 60)
    print(f"SECRET_KEY={secret_key}")
    print(f"JWT_SECRET_KEY={jwt_secret_key}")
    print("-" * 60)
    
    print("\nTo use these keys, add them to your backend/.env file:")
    print(f"""
# Flask Configuration
SECRET_KEY={secret_key}
JWT_SECRET_KEY={jwt_secret_key}
FLASK_ENV=development
DEBUG=True

# Database Configuration
DB_TYPE=mysql
DB_HOST=localhost
DB_PORT=3306
DB_NAME=threat_detection
DB_USER=root
DB_PASSWORD=your_password

# Simulation Mode
SIMULATION_MODE=true
""")
    
    print("\nOr you can copy individual values:")
    print(f"  SECRET_KEY={secret_key}")
    print(f"  JWT_SECRET_KEY={jwt_secret_key}")
