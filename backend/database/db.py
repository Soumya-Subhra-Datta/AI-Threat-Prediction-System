from database.models import db, User, ThreatEvent, BlockedIP, SystemLog, RemediationAction
import bcrypt

def init_db(app):
    """Initialize database and create tables"""
    with app.app_context():
        # Drop and recreate all tables to ensure fresh start
        db.drop_all()
        db.create_all()
        
        # Always create default users with correct passwords
        admin = User(
            username='admin',
            email='admin@threatdetection.local',
            is_admin=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        
        # Create demo user
        demo = User(
            username='demo',
            email='demo@threatdetection.local',
            is_admin=False
        )
        demo.set_password('demo123')
        db.session.add(demo)
        
        db.session.commit()
        print("Default users created: admin/admin123, demo/demo123")

def get_db():
    return db
