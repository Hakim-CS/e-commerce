from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity

from models import User

def admin_required(f):
    """
    Decorator to check if the current user has admin role
    Must be used after jwt_required()
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user or not user.has_role('admin'):
            return jsonify({"error": "Admin role required"}), 403
        
        return f(*args, **kwargs)
    
    return decorated

def permission_required(permission_code):
    """
    Decorator to check if the current user has a specific permission
    Must be used after jwt_required()
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user or not user.has_permission(permission_code):
                return jsonify({"error": f"Permission '{permission_code}' required"}), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    return decorator
