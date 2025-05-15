from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity

from app import db
from models import User, Role, Permission

bp = Blueprint('authz', __name__, url_prefix='/authz')

@bp.route('/permissions', methods=['GET'])
@jwt_required()
def get_permissions():
    """Fetch all permissions of the current user"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    permissions = []
    for role in user.roles:
        for permission in role.permissions:
            if permission.code not in [p['code'] for p in permissions]:
                permissions.append({
                    'code': permission.code,
                    'description': permission.description
                })
    
    return jsonify({
        "user_id": user.id,
        "username": user.username,
        "permissions": permissions
    })

@bp.route('/has-role', methods=['GET'])
@jwt_required()
def has_role():
    """Check if the user has a specific role"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    role_name = request.args.get('role')
    if not role_name:
        return jsonify({"error": "Role parameter is required"}), 400
    
    has_role = user.has_role(role_name)
    
    return jsonify({
        "user_id": user.id,
        "username": user.username,
        "role": role_name,
        "has_role": has_role
    })

@bp.route('/has-permission', methods=['GET'])
@jwt_required()
def has_permission():
    """Check if the user has a specific permission"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    permission_code = request.args.get('permission')
    if not permission_code:
        return jsonify({"error": "Permission parameter is required"}), 400
    
    has_permission = user.has_permission(permission_code)
    
    return jsonify({
        "user_id": user.id,
        "username": user.username,
        "permission": permission_code,
        "has_permission": has_permission
    })

@bp.route('/user-roles/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_roles(user_id):
    """Get the roles of a specific user (admin only)"""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or not current_user.has_role('admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    roles = [{"id": role.id, "name": role.name, "description": role.description} 
             for role in user.roles]
    
    return jsonify({
        "user_id": user.id,
        "username": user.username,
        "roles": roles
    })

@bp.route('/all-roles', methods=['GET'])
@jwt_required()
def get_all_roles():
    """Get all available roles (admin only)"""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or not current_user.has_role('admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    roles = Role.query.all()
    role_list = [{"id": role.id, "name": role.name, "description": role.description} 
                 for role in roles]
    
    return jsonify({"roles": role_list})

@bp.route('/all-permissions', methods=['GET'])
@jwt_required()
def get_all_permissions():
    """Get all available permissions (admin only)"""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or not current_user.has_role('admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    permissions = Permission.query.all()
    permission_list = [{"id": perm.id, "code": perm.code, "description": perm.description} 
                       for perm in permissions]
    
    return jsonify({"permissions": permission_list})
