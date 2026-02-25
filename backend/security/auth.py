from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from database.models import User
from database.db import db
from werkzeug.security import check_password_hash

def admin_required(fn):
    """Decorator to require admin privileges"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        identity = get_jwt_identity()
        user = User.query.filter_by(username=identity).first()
        if not user or not user.is_admin:
            return jsonify({'error': 'Admin privileges required'}), 403
        return fn(*args, **kwargs)
    return wrapper

def authenticate_user(username, password):
    """Authenticate a user and return user if valid"""
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        return user
    return None

def get_current_user():
    """Get the current authenticated user"""
    try:
        verify_jwt_in_request()
        identity = get_jwt_identity()
        return User.query.filter_by(username=identity).first()
    except:
        return None
