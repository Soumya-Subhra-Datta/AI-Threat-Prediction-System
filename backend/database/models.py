from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        """Hash and set the password"""
        import bcrypt
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        """Verify password against hash"""
        import bcrypt
        try:
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
        except:
            return False

class ThreatEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    threat_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    source_ip = db.Column(db.String(50))
    description = db.Column(db.Text)
    anomaly_score = db.Column(db.Float)
    status = db.Column(db.String(20), default='active')
    remediation_action = db.Column(db.String(100))

class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.String(200))
    blocked_until = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    level = db.Column(db.String(20), nullable=False)
    source = db.Column(db.String(50))
    message = db.Column(db.Text)
    details = db.Column(db.Text)

class RemediationAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action_type = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(100))
    status = db.Column(db.String(20), nullable=False)
    details = db.Column(db.Text)
    simulation_mode = db.Column(db.Boolean, default=True)
