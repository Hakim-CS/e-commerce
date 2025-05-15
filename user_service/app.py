import os
import logging
from datetime import timedelta

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure app
app.config.update(
    SECRET_KEY=os.environ.get("SESSION_SECRET", "super-secret-user-service-key"),
    SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/user_service"),
    SQLALCHEMY_ENGINE_OPTIONS={
        "pool_recycle": 300,
        "pool_pre_ping": True,
    },
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    JWT_SECRET_KEY=os.environ.get("JWT_SECRET_KEY", "super-secret-jwt-key"),
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=1),
    JWT_REFRESH_TOKEN_EXPIRES=timedelta(days=30),
)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# Import models to ensure they're registered with SQLAlchemy
with app.app_context():
    import models
    from routes import auth, authz, user, address_contact
    
    # Register blueprints
    app.register_blueprint(auth.bp)
    app.register_blueprint(authz.bp)
    app.register_blueprint(user.bp)
    app.register_blueprint(address_contact.bp)
    
    # Create all tables
    db.create_all()

    # Create initial admin user if it doesn't exist
    from models import User, Role, Permission, UserRole
    from werkzeug.security import generate_password_hash
    
    admin_role = Role.query.filter_by(name='admin').first()
    user_role = Role.query.filter_by(name='user').first()
    
    # Create roles if they don't exist
    if not admin_role:
        admin_role = Role(name='admin', description='Administrator')
        db.session.add(admin_role)
    
    if not user_role:
        user_role = Role(name='user', description='Regular user')
        db.session.add(user_role)
    
    # Create permissions if they don't exist
    permissions = [
        ('user.view', 'Can view user profiles'),
        ('user.edit', 'Can edit user profiles'),
        ('user.delete', 'Can delete users'),
        ('user.create', 'Can create users'),
        ('address.view', 'Can view addresses'),
        ('address.edit', 'Can edit addresses'),
        ('address.delete', 'Can delete addresses'),
        ('address.create', 'Can create addresses'),
        ('contact.view', 'Can view contacts'),
        ('contact.edit', 'Can edit contacts'),
        ('contact.delete', 'Can delete contacts'),
        ('contact.create', 'Can create contacts'),
    ]
    
    for code, description in permissions:
        if not Permission.query.filter_by(code=code).first():
            permission = Permission(code=code, description=description)
            db.session.add(permission)
    
    # Create admin user if it doesn't exist
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),
            is_active=True,
            first_name='Admin',
            last_name='User'
        )
        db.session.add(admin_user)
        db.session.commit()
        
        # Assign admin role to admin user
        user_role = UserRole(user_id=admin_user.id, role_id=admin_role.id)
        db.session.add(user_role)
    
    db.session.commit()
