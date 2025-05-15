import os
import requests
import json
from functools import wraps
from flask import request, jsonify, redirect, url_for, flash, session, current_app
from werkzeug.local import LocalProxy

# Get the user service URL from environment or use default
USER_SERVICE_URL = os.environ.get("USER_SERVICE_URL", "http://localhost:8000")

def login_required(f):
    """
    Decorator to check if user is logged in
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.headers.get('Accept') == 'application/json' or request.is_json:
                return jsonify({"error": "Authentication required"}), 401
            else:
                flash("Please log in to access this page", "warning")
                return redirect(url_for('product.login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """
    Decorator to check if user is an admin
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.headers.get('Accept') == 'application/json' or request.is_json:
                return jsonify({"error": "Authentication required"}), 401
            else:
                flash("Please log in to access this page", "warning")
                return redirect(url_for('product.login'))
        
        # Check if admin flag is in session
        if not session.get('is_admin', False):
            # If not in session, check with user service
            has_admin_role = check_user_role('admin')
            if not has_admin_role:
                if request.headers.get('Accept') == 'application/json' or request.is_json:
                    return jsonify({"error": "Admin access required"}), 403
                else:
                    flash("Admin access required", "danger")
                    return redirect(url_for('product.list_products'))
            # Store admin status in session
            session['is_admin'] = True
        
        return f(*args, **kwargs)
    return decorated

def permission_required(permission_code):
    """
    Decorator to check if user has a specific permission
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                if request.headers.get('Accept') == 'application/json' or request.is_json:
                    return jsonify({"error": "Authentication required"}), 401
                else:
                    flash("Please log in to access this page", "warning")
                    return redirect(url_for('product.login'))
            
            # Check permission with user service
            has_permission = check_user_permission(permission_code)
            if not has_permission:
                if request.headers.get('Accept') == 'application/json' or request.is_json:
                    return jsonify({"error": f"Permission '{permission_code}' required"}), 403
                else:
                    flash("You don't have permission to perform this action", "danger")
                    return redirect(url_for('product.list_products'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_user_role(role_name):
    """
    Check if the current user has a specific role
    """
    try:
        # Get token from session
        token = session.get('access_token')
        if not token:
            return False
        
        # Call user service API
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            f"{USER_SERVICE_URL}/authz/has-role?role={role_name}",
            headers=headers
        )
        
        # Check response
        if response.status_code == 200:
            data = response.json()
            return data.get('has_role', False)
        
        return False
    except Exception as e:
        current_app.logger.error(f"Error checking user role: {str(e)}")
        return False

def check_user_permission(permission_code):
    """
    Check if the current user has a specific permission
    """
    try:
        # Get token from session
        token = session.get('access_token')
        if not token:
            return False
        
        # Call user service API
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            f"{USER_SERVICE_URL}/authz/has-permission?permission={permission_code}",
            headers=headers
        )
        
        # Check response
        if response.status_code == 200:
            data = response.json()
            return data.get('has_permission', False)
        
        return False
    except Exception as e:
        current_app.logger.error(f"Error checking user permission: {str(e)}")
        return False

def get_user_info():
    """
    Get current user info from user service
    """
    try:
        # Get token from session
        token = session.get('access_token')
        if not token:
            return None
        
        # Call user service API
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(f"{USER_SERVICE_URL}/user/me", headers=headers)
        
        # Check response
        if response.status_code == 200:
            return response.json()
        
        return None
    except Exception as e:
        current_app.logger.error(f"Error getting user info: {str(e)}")
        return None
