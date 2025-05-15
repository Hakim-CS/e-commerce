from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, get_jwt_identity,
    get_jwt, set_access_cookies, set_refresh_cookies, unset_jwt_cookies
)
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timezone, timedelta
import uuid

from app import db, jwt
from models import User, Token

bp = Blueprint('auth', __name__, url_prefix='/auth')

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = db.session.query(Token).filter_by(jti=jti).first()
    return token is not None and token.revoked

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            # Handle API login
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            # Handle form login
            username = request.form.get('username')
            password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            if request.is_json:
                return jsonify({"error": "Invalid username or password"}), 401
            else:
                flash('Invalid username or password', 'danger')
                return render_template('login.html')
        
        if not user.is_active:
            if request.is_json:
                return jsonify({"error": "Account is deactivated"}), 401
            else:
                flash('Account is deactivated. Please contact administrator.', 'danger')
                return render_template('login.html')
        
        # Create tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        # Store refresh token in database
        access_jti = get_jwt()["jti"] if get_jwt() else str(uuid.uuid4())
        refresh_jti = str(uuid.uuid4())  # Generate a JTI for refresh token
        
        db.session.add(Token(
            user_id=user.id,
            jti=refresh_jti,
            token_type="refresh",
            revoked=False,
            expires=datetime.now(timezone.utc) + timedelta(days=30)
        ))
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "is_admin": user.has_role('admin'),
                    "is_active": user.is_active
                }
            })
        else:
            response = redirect(url_for('user.profile'))
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)
            session['user_id'] = user.id
            session['is_admin'] = user.has_role('admin')
            return response
    
    return render_template('login.html')

@bp.route('/logout', methods=['POST'])
@jwt_required(optional=True)
def logout():
    # Get JWT token if available
    current_token = get_jwt()
    
    if current_token:
        jti = current_token["jti"]
        # Add token to blocklist
        token = Token.query.filter_by(jti=jti).first()
        if token:
            token.revoked = True
            db.session.commit()
    
    # Clear session
    session.clear()
    
    if request.is_json:
        return jsonify({"message": "Successfully logged out"}), 200
    else:
        response = redirect(url_for('auth.login'))
        unset_jwt_cookies(response)
        flash('You have been logged out', 'success')
        return response

@bp.route('/checkLogin', methods=['GET'])
@jwt_required(optional=True)
def check_login():
    current_identity = get_jwt_identity()
    
    if current_identity:
        user = User.query.get(current_identity)
        if user and user.is_active:
            if request.is_json:
                return jsonify({
                    "authenticated": True,
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "is_admin": user.has_role('admin'),
                        "is_active": user.is_active
                    }
                })
            else:
                # For browser clients, just return success
                return jsonify({"authenticated": True})
    
    # User not authenticated or token expired
    if request.is_json:
        return jsonify({"authenticated": False}), 401
    else:
        # Redirect browser clients to login page
        return jsonify({"authenticated": False}), 401

@bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user or not user.is_active:
        return jsonify({"error": "User not found or inactive"}), 401
    
    access_token = create_access_token(identity=current_user_id)
    
    if request.is_json:
        return jsonify({"access_token": access_token})
    else:
        response = jsonify({"refresh": True})
        set_access_cookies(response, access_token)
        return response
