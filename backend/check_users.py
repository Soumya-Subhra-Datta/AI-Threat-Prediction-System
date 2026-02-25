from app import app, db
from database.models import User

with app.app_context():
    users = User.query.all()
    print(f'Total users: {len(users)}')
    for u in users:
        print(f'Username: {u.username}, Email: {u.email}, is_admin: {u.is_admin}, hash: {u.password_hash[:30]}...')
        
        # Test password
        test_result = u.check_password('admin123')
        print(f'  Password test for admin123: {test_result}')
