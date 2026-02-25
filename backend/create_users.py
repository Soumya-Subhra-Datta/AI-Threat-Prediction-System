"""
Create test users for the threat detection system
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from database.models import User

def create_users():
    with app.app_context():
        # Drop and recreate all tables
        db.drop_all()
        db.create_all()
        
        # Create admin user
        admin = User(username='admin', email='admin@demo.local')
        admin.set_password('admin123')
        admin.is_admin = True
        db.session.add(admin)
        
        # Create demo user
        demo = User(username='demo', email='demo@demo.local')
        demo.set_password('demo123')
        demo.is_admin = False
        db.session.add(demo)
        
        db.session.commit()
        
        print("Users created successfully!")
        print("Admin: admin / admin123")
        print("Demo: demo / demo123")
        
        # Verify users
        users = User.query.all()
        for u in users:
            print(f"User: {u.username}, Admin: {u.is_admin}, Hash: {u.password_hash[:30]}...")

if __name__ == '__main__':
    create_users()
