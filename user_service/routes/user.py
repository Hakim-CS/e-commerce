from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash

from app import db
from models import User, Role, UserRole
from utils.auth import admin_required

bp = Blueprint('user', __name__, url_prefix='/user')

@bp.route('/', methods=['GET'])
@jwt_required()
@admin_required
def get_all_users():
    """Get all users (admin only)"""
    users = User.query.all()
    
    if request.is_json:
        return jsonify({
            "users": [{
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_active": user.is_active,
                "roles": [role.name for role in user.roles],
                "created_at": user.created_at.isoformat(),
                "updated_at": user.updated_at.isoformat()
            } for user in users]
        })
    else:
        return render_template('admin/users.html', users=users)

@bp.route('/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Get user details"""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    # Check if admin or the user is requesting their own data
    if current_user_id != user_id and not current_user.has_role('admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if request.is_json:
        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_active": user.is_active,
            "roles": [role.name for role in user.roles],
            "created_at": user.created_at.isoformat(),
            "updated_at": user.updated_at.isoformat()
        })
    else:
        if current_user.has_role('admin'):
            return render_template('admin/user_detail.html', user=user)
        else:
            return render_template('user/profile.html', user=user)

@bp.route('/', methods=['POST'])
@jwt_required()
@admin_required
def create_user():
    """Create a new user (admin only)"""
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    role_ids = data.getlist('role_ids') if hasattr(data, 'getlist') else data.get('role_ids', [])
    
    if not username or not email or not password:
        if request.is_json:
            return jsonify({"error": "Username, email, and password are required"}), 400
        else:
            flash('Username, email, and password are required', 'danger')
            return redirect(url_for('user.get_all_users'))
    
    # Check if user already exists
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        if request.is_json:
            return jsonify({"error": "Username or email already exists"}), 400
        else:
            flash('Username or email already exists', 'danger')
            return redirect(url_for('user.get_all_users'))
    
    # Create new user
    new_user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        first_name=first_name,
        last_name=last_name,
        is_active=True
    )
    db.session.add(new_user)
    db.session.commit()
    
    # Assign roles if provided
    if role_ids:
        for role_id in role_ids:
            role = Role.query.get(role_id)
            if role:
                user_role = UserRole(user_id=new_user.id, role_id=role.id)
                db.session.add(user_role)
        db.session.commit()
    
    if request.is_json:
        return jsonify({
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "first_name": new_user.first_name,
            "last_name": new_user.last_name,
            "is_active": new_user.is_active,
            "message": "User created successfully"
        }), 201
    else:
        flash('User created successfully', 'success')
        return redirect(url_for('user.get_all_users'))

@bp.route('/<int:user_id>', methods=['PUT', 'POST'])
@jwt_required()
def update_user(user_id):
    """Update user details"""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    # Check if admin or the user is updating their own data
    if current_user_id != user_id and not current_user.has_role('admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    # Only admins can change these fields
    if current_user.has_role('admin'):
        if 'username' in data:
            user.username = data.get('username')
        if 'email' in data:
            user.email = data.get('email')
        if 'is_active' in data:
            user.is_active = data.get('is_active') in ['true', 'True', True, 1, '1']
        
        # Update roles if provided
        if 'role_ids' in data:
            role_ids = data.getlist('role_ids') if hasattr(data, 'getlist') else data.get('role_ids', [])
            # Remove all existing roles
            for role in user.roles:
                user.roles.remove(role)
            # Add new roles
            for role_id in role_ids:
                role = Role.query.get(role_id)
                if role:
                    user.roles.append(role)
    
    # Fields that all users can update for themselves
    if 'first_name' in data:
        user.first_name = data.get('first_name')
    if 'last_name' in data:
        user.last_name = data.get('last_name')
    
    db.session.commit()
    
    if request.is_json:
        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_active": user.is_active,
            "roles": [role.name for role in user.roles],
            "message": "User updated successfully"
        })
    else:
        flash('User updated successfully', 'success')
        if current_user.has_role('admin'):
            return redirect(url_for('user.get_all_users'))
        else:
            return redirect(url_for('user.get_user', user_id=user.id))

@bp.route('/<int:user_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_user(user_id):
    """Delete a user (soft delete)"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Soft delete by deactivating
    user.is_active = False
    db.session.commit()
    
    if request.is_json:
        return jsonify({
            "id": user.id,
            "message": "User deactivated successfully"
        })
    else:
        flash('User deactivated successfully', 'success')
        return redirect(url_for('user.get_all_users'))

@bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change user's password"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if not old_password or not new_password:
        if request.is_json:
            return jsonify({"error": "Old and new passwords are required"}), 400
        else:
            flash('Old and new passwords are required', 'danger')
            return redirect(url_for('user.get_user', user_id=user.id))
    
    from werkzeug.security import check_password_hash
    if not check_password_hash(user.password_hash, old_password):
        if request.is_json:
            return jsonify({"error": "Old password is incorrect"}), 400
        else:
            flash('Old password is incorrect', 'danger')
            return redirect(url_for('user.get_user', user_id=user.id))
    
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    
    if request.is_json:
        return jsonify({"message": "Password changed successfully"})
    else:
        flash('Password changed successfully', 'success')
        return redirect(url_for('user.get_user', user_id=user.id))

@bp.route('/reset-password/<int:user_id>', methods=['POST'])
@jwt_required()
@admin_required
def reset_password(user_id):
    """Reset a user's password (admin only)"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    new_password = data.get('new_password')
    
    if not new_password:
        if request.is_json:
            return jsonify({"error": "New password is required"}), 400
        else:
            flash('New password is required', 'danger')
            return redirect(url_for('user.get_user', user_id=user.id))
    
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    
    if request.is_json:
        return jsonify({"message": "Password reset successfully"})
    else:
        flash('Password reset successfully', 'success')
        return redirect(url_for('user.get_user', user_id=user.id))

@bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get the currently logged in user"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if request.is_json:
        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_active": user.is_active,
            "roles": [role.name for role in user.roles]
        })
    else:
        return redirect(url_for('user.get_user', user_id=user.id))

@bp.route('/deactivate/<int:user_id>', methods=['POST'])
@jwt_required()
@admin_required
def deactivate_user(user_id):
    """Deactivate another user (admin only)"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    user.is_active = False
    db.session.commit()
    
    if request.is_json:
        return jsonify({
            "id": user.id,
            "message": "User deactivated successfully"
        })
    else:
        flash('User deactivated successfully', 'success')
        return redirect(url_for('user.get_all_users'))

@bp.route('/deactivate-self', methods=['POST'])
@jwt_required()
def deactivate_self():
    """User deactivates their own account"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    user.is_active = False
    db.session.commit()
    
    if request.is_json:
        return jsonify({
            "id": user.id,
            "message": "Your account has been deactivated"
        })
    else:
        flash('Your account has been deactivated', 'success')
        return redirect(url_for('auth.logout'))
