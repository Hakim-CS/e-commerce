import os
import logging
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, redirect, url_for, flash, request, session
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, get_jwt_identity, jwt_required
from urllib.parse import urlparse
from decimal import Decimal
from functools import wraps
from dotenv import load_dotenv
from flask_cors import CORS

def initialize_database():
    """Initialize database with required data"""
    try:
        with app.app_context():
            db.create_all()
            
            # Add roles if they don't exist
            roles = {
                'admin': 'Administrator with full access',
                'user': 'Regular user with limited access',
                'manager': 'Store manager with product management access'
            }
            
            for role_name, description in roles.items():
                if not Role.query.filter_by(name=role_name).first():
                    role = Role(name=role_name, description=description)
                    db.session.add(role)
            
            # Add permissions if they don't exist
            permissions = {
                'user.view': 'View user details',
                'user.edit': 'Edit user details',
                'user.delete': 'Delete users',
                'product.view': 'View products',
                'product.create': 'Create products',
                'product.edit': 'Edit products',
                'product.delete': 'Delete products',
                'order.view': 'View orders',
                'order.create': 'Create orders',
                'order.edit': 'Edit orders',
                'order.delete': 'Delete orders',
            }
            
            for perm_code, description in permissions.items():
                if not Permission.query.filter_by(code=perm_code).first():
                    permission = Permission(code=perm_code, description=description)
                    db.session.add(permission)
            
            # Create admin user if it doesn't exist
            if not User.query.filter_by(username='admin').first():
                admin_user = User(
                    username='admin',
                    email='admin@example.com',
                    first_name='Admin',
                    last_name='User',
                    is_active=True
                )
                admin_user.set_password('admin123')
                
                # Add admin role
                admin_role = Role.query.filter_by(name='admin').first()
                if admin_role:
                    admin_user.roles.append(admin_role)
                
                db.session.add(admin_user)
            
            # Add sample products if there are none
            if Product.query.count() == 0:
                sample_products = [
                    {
                        'name': 'Smartphone X1',
                        'sku': 'PHONE-X1',
                        'barcode': '1234567890123',
                        'description': 'Latest model smartphone with 6.5" OLED display, 128GB storage, and triple camera system.',
                        'price': 599.99,
                        'stock': 50
                    },
                    {
                        'name': 'Laptop Pro 15',
                        'sku': 'LAPTOP-P15',
                        'barcode': '1234567890124',
                        'description': 'Professional laptop with 15" display, 16GB RAM, 512GB SSD, and dedicated graphics card.',
                        'price': 1299.99,
                        'stock': 25
                    },
                    {
                        'name': 'Wireless Headphones',
                        'sku': 'AUDIO-WH1',
                        'barcode': '1234567890125',
                        'description': 'Premium wireless headphones with noise cancellation, 30-hour battery life, and high-definition audio.',
                        'price': 199.99,
                        'stock': 100
                    },
                    {
                        'name': 'Smart Watch',
                        'sku': 'WATCH-SW1',
                        'barcode': '1234567890126',
                        'description': 'Fitness and health tracking smartwatch with heart rate monitor, GPS, and 7-day battery life.',
                        'price': 149.99,
                        'stock': 75
                    },
                    {
                        'name': 'Bluetooth Speaker',
                        'sku': 'AUDIO-BS1',
                        'barcode': '1234567890127',
                        'description': 'Portable Bluetooth speaker with 360° sound, waterproof design, and 12-hour battery life.',
                        'price': 79.99,
                        'stock': 120
                    },
                    {
                        'name': 'Tablet Pro',
                        'sku': 'TABLET-P1',
                        'barcode': '1234567890128',
                        'description': '10.5" tablet with high-resolution display, 64GB storage, and all-day battery life.',
                        'price': 349.99,
                        'stock': 40
                    },
                    {
                        'name': 'Wireless Charger',
                        'sku': 'ACC-WC1',
                        'barcode': '1234567890129',
                        'description': 'Fast wireless charging pad compatible with most modern smartphones and accessories.',
                        'price': 29.99,
                        'stock': 150
                    },
                    {
                        'name': 'Gaming Console',
                        'sku': 'GAME-C1',
                        'barcode': '1234567890130',
                        'description': 'Next-generation gaming console with 1TB storage, 4K graphics, and includes one controller.',
                        'price': 499.99,
                        'stock': 30
                    }
                ]
                
                for product_data in sample_products:
                    product = Product(
                        name=product_data['name'],
                        sku=product_data['sku'],
                        barcode=product_data['barcode'],
                        description=product_data['description'],
                        price=product_data['price'],
                        stock=product_data['stock']
                    )
                    db.session.add(product)
                
                logger.info("Added sample products to the database")
            
            db.session.commit()
            logger.info("Database initialized with roles, permissions, admin user, and products")
    
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")

from models import db, User, Role, Permission, Product, Cart, CartItem, Order, OrderItem, Token
from forms import LoginForm, RegistrationForm, ChangePasswordForm, ProfileForm

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Create Flask app
app = Flask(__name__, template_folder='templates')
# Add right after that:⚠️
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})
app.secret_key = os.environ.get("SESSION_SECRET", "super-secret-key")


# Configure SQLAlchemy
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize Flask-JWT-Extended
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", app.secret_key)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app) 

# Custom JWT claims to include user info
@jwt.additional_claims_loader
def add_claims_to_access_token(identity):
    user = User.query.get(identity)
    if not user:
        return {}
        
    return {
        "username": user.username,
        "email": user.email,
        "roles": [role.name for role in user.roles]
    }

# JWT token required decorator with role check
def jwt_role_required(role_name):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            # Get user identity from JWT
            identity = get_jwt_identity()
            user = User.query.get(identity)
            
            # Check if user exists and has the required role
            if not user or not user.has_role(role_name):
                return jsonify({"message": "Access denied"}), 403
                
            return fn(*args, **kwargs)
        return wrapper
    return decorator

@login_manager.user_loader
def load_user(user_id):
    """Load user from database for Flask-Login"""
    return User.query.get(int(user_id))

@app.route('/')
def index():
    """Main landing page"""
    # Get a few featured products (newest, non-deleted products)
    featured_products = Product.query.filter_by(is_deleted=False).order_by(Product.created_at.desc()).limit(4).all()
    return render_template('index.html', title='Home', featured_products=featured_products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('index')
            
        return redirect(next_page)
    
    return render_template('auth/login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data
        )
        user.set_password(form.password.data)
        
        # Add user role
        user_role = Role.query.filter_by(name='user').first()
        if user_role:
            user.roles.append(user_role)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html', title='Register', form=form)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile page"""
    form = ProfileForm()
    
    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        
        # Check if email has changed
        if current_user.email != form.email.data:
            # Check if new email is already taken
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already in use by another account.', 'danger')
                return redirect(url_for('profile'))
            
            current_user.email = form.email.data
        
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    
    # Pre-populate form fields
    if request.method == 'GET':
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.email.data = current_user.email
    
    return render_template('user/profile.html', title='Profile', form=form)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password page"""
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        if not current_user.check_password(form.old_password.data):
            flash('Your current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))
        
        current_user.set_password(form.new_password.data)
        db.session.commit()
        
        flash('Your password has been updated!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('user/change_password.html', title='Change Password', form=form)

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "ok", "message": "E-Commerce API is running"})

# JWT Authentication API Endpoints
@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """API endpoint for user login and token generation"""
    # Check if required fields are provided
    if not request.is_json:
        return jsonify({"message": "Missing JSON in request"}), 400
        
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    
    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400
    
    # Authenticate user
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"message": "Invalid username or password"}), 401
    
    # Check if user is active
    if not user.is_active:
        return jsonify({"message": "Account is inactive"}), 403
    
    # Generate tokens
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    
    # Store refresh token in database
    token_jti = str(uuid.uuid4())
    expires = datetime.utcnow() + app.config["JWT_REFRESH_TOKEN_EXPIRES"]
    
    db_token = Token(
        user_id=user.id,
        jti=token_jti,
        token_type='refresh',
        expires=expires
    )
    
    try:
        db.session.add(db_token)
        db.session.commit()
        
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "roles": [role.name for role in user.roles]
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error storing refresh token: {str(e)}")
        return jsonify({"message": "Error generating token"}), 500

@app.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    """Refresh an access token using a refresh token"""
    # Get user identity from refresh token
    identity = get_jwt_identity()
    
    # Check if user still exists and is active
    user = User.query.get(identity)
    if not user or not user.is_active:
        return jsonify({"message": "User not found or inactive"}), 401
    
    # Generate new access token
    access_token = create_access_token(identity=identity)
    
    return jsonify({
        "access_token": access_token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email
        }
    }), 200

@app.route('/api/auth/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    """Get the current user's profile (JWT protected)"""
    # Get user identity from access token
    identity = get_jwt_identity()
    
    # Find user in database
    user = User.query.get(identity)
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    # Return user profile
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "roles": [role.name for role in user.roles]
    }), 200

# Product Routes
@app.route('/products', methods=['GET'])
def list_products():
    """List all active products"""
    # Get query parameters for filtering and pagination
    search = request.args.get('search', '')
    sort_by = request.args.get('sort', 'name')
    sort_order = request.args.get('order', 'asc')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 12, type=int)
    
    # Build query
    query = Product.query.filter_by(is_deleted=False)
    
    # Apply search if provided
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Product.name.ilike(search_term),
                Product.description.ilike(search_term),
                Product.sku.ilike(search_term),
                Product.barcode.ilike(search_term)
            )
        )
    
    # Apply sorting
    if sort_by == 'price':
        order_col = Product.price
    elif sort_by == 'name':
        order_col = Product.name
    elif sort_by == 'created_at':
        order_col = Product.created_at
    else:
        order_col = Product.name
    
    if sort_order == 'desc':
        query = query.order_by(order_col.desc())
    else:
        query = query.order_by(order_col.asc())
    
    # Paginate results
    products = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template(
        'products/list.html', 
        products=products,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order
    )

@app.route('/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    """Get details of a specific product"""
    product = Product.query.get_or_404(product_id)
    
    # Don't show deleted products unless admin
    if product.is_deleted and not current_user.is_authenticated and not current_user.has_role('admin'):
        flash("Product not found", "danger")
        return redirect(url_for('list_products'))
    
    return render_template('products/detail.html', product=product)

@app.route('/admin/products', methods=['GET'])
@login_required
def admin_products():
    """Admin view for managing products"""
    if not current_user.has_role('admin'):
        flash("You don't have permission to access this page", "danger")
        return redirect(url_for('index'))
        
    # Get query parameters for filtering and pagination
    search = request.args.get('search', '')
    status = request.args.get('status', 'active')
    sort_by = request.args.get('sort', 'id')
    sort_order = request.args.get('order', 'desc')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # Build query
    query = Product.query
    
    # Apply status filter
    if status == 'active':
        query = query.filter_by(is_deleted=False)
    elif status == 'deleted':
        query = query.filter_by(is_deleted=True)
    # 'all' status does not filter
    
    # Apply search if provided
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Product.name.ilike(search_term),
                Product.sku.ilike(search_term),
                Product.barcode.ilike(search_term)
            )
        )
    
    # Apply sorting
    if sort_by == 'name':
        order_col = Product.name
    elif sort_by == 'price':
        order_col = Product.price
    elif sort_by == 'stock':
        order_col = Product.stock
    elif sort_by == 'created_at':
        order_col = Product.created_at
    else:
        order_col = Product.id
    
    if sort_order == 'asc':
        query = query.order_by(order_col.asc())
    else:
        query = query.order_by(order_col.desc())
    
    # Paginate results
    products = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template(
        'admin/products.html',
        products=products,
        search=search,
        status=status,
        sort_by=sort_by,
        sort_order=sort_order
    )

@app.route('/admin/products/new', methods=['GET'])
@login_required
def new_product():
    """Admin form for creating a new product"""
    if not current_user.has_role('admin'):
        flash("You don't have permission to access this page", "danger")
        return redirect(url_for('index'))
        
    return render_template('admin/product_edit.html', product=None, is_new=True)

@app.route('/admin/products/<int:product_id>/edit', methods=['GET'])
@login_required
def edit_product(product_id):
    """Admin form for editing a product"""
    if not current_user.has_role('admin'):
        flash("You don't have permission to access this page", "danger")
        return redirect(url_for('index'))
        
    product = Product.query.get_or_404(product_id)
    return render_template('admin/product_edit.html', product=product, is_new=False)

@app.route('/admin/products/<int:product_id>/delete', methods=['POST'])
@login_required
def admin_delete_product(product_id):
    """Admin route to delete a product"""
    if not current_user.has_role('admin'):
        flash("You don't have permission to perform this action", "danger")
        return redirect(url_for('index'))
        
    product = Product.query.get_or_404(product_id)
    
    try:
        # Soft delete by setting is_deleted flag
        product.is_deleted = True
        db.session.commit()
        
        flash(f"Product '{product.name}' deleted successfully", "success")
        return redirect(url_for('admin_products'))
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting product: {str(e)}")
        
        flash(f"Error deleting product: {str(e)}", "danger")
        return redirect(url_for('admin_products'))

# Admin user management routes
@app.route('/admin/users', methods=['GET'])
@login_required
def admin_users():
    """Admin view for managing users"""
    if not current_user.has_role('admin'):
        flash("You don't have permission to access this page", "danger")
        return redirect(url_for('index'))
        
    # Get query parameters for filtering and pagination
    search = request.args.get('search', '')
    status = request.args.get('status', 'active')
    sort_by = request.args.get('sort', 'id')
    sort_order = request.args.get('order', 'desc')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # Build query
    query = User.query
    
    # Apply status filter
    if status == 'active':
        query = query.filter_by(is_active=True)
    elif status == 'inactive':
        query = query.filter_by(is_active=False)
    # 'all' status does not filter
    
    # Apply search if provided
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                User.username.ilike(search_term),
                User.email.ilike(search_term),
                User.first_name.ilike(search_term),
                User.last_name.ilike(search_term)
            )
        )
    
    # Apply sorting
    if sort_by == 'username':
        order_col = User.username
    elif sort_by == 'email':
        order_col = User.email
    elif sort_by == 'created_at':
        order_col = User.created_at
    else:
        order_col = User.id
    
    if sort_order == 'asc':
        query = query.order_by(order_col.asc())
    else:
        query = query.order_by(order_col.desc())
    
    # Paginate results
    users = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get all available roles for the user creation/edit form
    roles = Role.query.all()
    
    return render_template(
        'admin/users.html',
        users=users,
        roles=roles,
        search=search,
        status=status,
        sort_by=sort_by,
        sort_order=sort_order
    )

@app.route('/admin/users/new', methods=['GET'])
@login_required
def new_user():
    """Admin form for creating a new user"""
    if not current_user.has_role('admin'):
        flash("You don't have permission to access this page", "danger")
        return redirect(url_for('index'))
        
    # Get all available roles for the form
    roles = Role.query.all()
    return render_template('admin/user_edit.html', user=None, roles=roles, is_new=True)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET'])
@login_required
def edit_user(user_id):
    """Admin form for editing a user"""
    if not current_user.has_role('admin'):
        flash("You don't have permission to access this page", "danger")
        return redirect(url_for('index'))
        
    user = User.query.get_or_404(user_id)
    
    # Get all available roles for the form
    roles = Role.query.all()
    return render_template('admin/user_edit.html', user=user, roles=roles, is_new=False)

@app.route('/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    """Admin route to activate/deactivate a user"""
    if not current_user.has_role('admin'):
        flash("You don't have permission to perform this action", "danger")
        return redirect(url_for('index'))
        
    user = User.query.get_or_404(user_id)
    
    # Don't allow deactivating yourself
    if user.id == current_user.id:
        flash("You cannot deactivate your own account", "danger")
        return redirect(url_for('admin_users'))
    
    try:
        # Toggle status
        user.is_active = not user.is_active
        db.session.commit()
        
        status = "activated" if user.is_active else "deactivated"
        flash(f"User '{user.username}' {status} successfully", "success")
        return redirect(url_for('admin_users'))
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error toggling user status: {str(e)}")
        
        flash(f"Error updating user status: {str(e)}", "danger")
        return redirect(url_for('admin_users'))

@app.route('/admin/users/create', methods=['POST'])
@login_required
def create_user():
    """Create a new user (admin only)"""
    if not current_user.has_role('admin'):
        flash("You don't have permission to perform this action", "danger")
        return redirect(url_for('index'))
    
    # Validate required fields
    required_fields = ['username', 'email', 'password', 'first_name', 'last_name']
    for field in required_fields:
        if not request.form.get(field):
            flash(f"Field '{field}' is required", "danger")
            return redirect(url_for('new_user'))
    
    # Check for duplicate username or email
    existing_user = User.query.filter(
        (User.username == request.form.get('username')) | 
        (User.email == request.form.get('email'))
    ).first()
    
    if existing_user:
        flash("A user with this username or email already exists", "danger")
        return redirect(url_for('new_user'))
    
    try:
        # Create new user
        new_user = User(
            username=request.form.get('username'),
            email=request.form.get('email'),
            first_name=request.form.get('first_name'),
            last_name=request.form.get('last_name'),
            is_active=request.form.get('is_active') in ['on', 'true', 'True', '1', 1, True]
        )
        new_user.set_password(request.form.get('password'))
        
        # Add roles
        role_ids = request.form.getlist('roles')
        for role_id in role_ids:
            role = Role.query.get(int(role_id))
            if role:
                new_user.roles.append(role)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash(f"User '{new_user.username}' created successfully", "success")
        return redirect(url_for('admin_users'))
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user: {str(e)}")
        
        flash(f"Error creating user: {str(e)}", "danger")
        return redirect(url_for('new_user'))

@app.route('/admin/users/<int:user_id>/update', methods=['POST'])
@login_required
def update_user(user_id):
    """Update a user (admin only)"""
    if not current_user.has_role('admin'):
        flash("You don't have permission to perform this action", "danger")
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    # Validate required fields
    required_fields = ['username', 'email', 'first_name', 'last_name']
    for field in required_fields:
        if not request.form.get(field):
            flash(f"Field '{field}' is required", "danger")
            return redirect(url_for('edit_user', user_id=user_id))
    
    # Check for duplicate username or email (excluding this user)
    existing_user = User.query.filter(
        db.or_(
            User.username == request.form.get('username'),
            User.email == request.form.get('email')
        ),
        User.id != user_id
    ).first()
    
    if existing_user:
        flash("Another user with this username or email already exists", "danger")
        return redirect(url_for('edit_user', user_id=user_id))
    
    try:
        # Update user fields
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        user.is_active = request.form.get('is_active') in ['on', 'true', 'True', '1', 1, True]
        
        # Update password if provided
        if request.form.get('password'):
            user.set_password(request.form.get('password'))
        
        # Update roles (remove all and add selected)
        user.roles = []
        role_ids = request.form.getlist('roles')
        for role_id in role_ids:
            role = Role.query.get(int(role_id))
            if role:
                user.roles.append(role)
        
        db.session.commit()
        
        flash(f"User '{user.username}' updated successfully", "success")
        return redirect(url_for('admin_users'))
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating user: {str(e)}")
        
        flash(f"Error updating user: {str(e)}", "danger")
        return redirect(url_for('edit_user', user_id=user_id))

@app.route('/product', methods=['POST'])
@login_required
def create_product():
    """Create a new product (admin only)"""
    if not current_user.has_role('admin'):
        flash("You don't have permission to perform this action", "danger")
        return redirect(url_for('index'))
    
    # Validate required fields
    required_fields = ['name', 'sku', 'barcode', 'price']
    for field in required_fields:
        if not request.form.get(field):
            flash(f"Field '{field}' is required", "danger")
            return redirect(url_for('new_product'))
    
    # Check for duplicate SKU or barcode
    existing_product = Product.query.filter(
        (Product.sku == request.form.get('sku')) | 
        (Product.barcode == request.form.get('barcode'))
    ).first()
    
    if existing_product:
        flash("A product with this SKU or barcode already exists", "danger")
        return redirect(url_for('new_product'))
    
    try:
        # Create new product
        new_product = Product(
            name=request.form.get('name'),
            sku=request.form.get('sku'),
            barcode=request.form.get('barcode'),
            description=request.form.get('description', ''),
            price=float(request.form.get('price')),
            stock=int(request.form.get('stock', 0))
        )
        
        db.session.add(new_product)
        db.session.commit()
        
        flash(f"Product '{new_product.name}' created successfully", "success")
        return redirect(url_for('admin_products'))
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating product: {str(e)}")
        
        flash(f"Error creating product: {str(e)}", "danger")
        return redirect(url_for('new_product'))

@app.route('/product/<int:product_id>', methods=['POST'])
@login_required
def update_product(product_id):
    """Update a product (admin only)"""
    if not current_user.has_role('admin'):
        flash("You don't have permission to perform this action", "danger")
        return redirect(url_for('index'))
        
    product = Product.query.get_or_404(product_id)
    
    try:
        # Update product fields if provided
        if 'name' in request.form:
            product.name = request.form.get('name')
        if 'sku' in request.form:
            # Check for duplicate SKU
            existing = Product.query.filter(Product.sku == request.form.get('sku'), Product.id != product_id).first()
            if existing:
                flash("A product with this SKU already exists", "danger")
                return redirect(url_for('edit_product', product_id=product_id))
            product.sku = request.form.get('sku')
        if 'barcode' in request.form:
            # Check for duplicate barcode
            existing = Product.query.filter(Product.barcode == request.form.get('barcode'), Product.id != product_id).first()
            if existing:
                flash("A product with this barcode already exists", "danger")
                return redirect(url_for('edit_product', product_id=product_id))
            product.barcode = request.form.get('barcode')
        if 'description' in request.form:
            product.description = request.form.get('description')
        if 'price' in request.form:
            product.price = float(request.form.get('price'))
        if 'stock' in request.form:
            product.stock = int(request.form.get('stock'))
        if 'is_deleted' in request.form:
            product.is_deleted = request.form.get('is_deleted') in [True, 'true', 'True', 1, '1', 'on']
        
        db.session.commit()
        
        flash(f"Product '{product.name}' updated successfully", "success")
        return redirect(url_for('admin_products'))
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating product: {str(e)}")
        
        flash(f"Error updating product: {str(e)}", "danger")
        return redirect(url_for('edit_product', product_id=product_id))

# Cart Routes
@app.route('/cart', methods=['GET'])
def view_cart():
    """View shopping cart"""
    # Get cart from session or create a new one
    if current_user.is_authenticated:
        # Get user's active cart or create new
        cart = Cart.query.filter_by(user_id=current_user.id, status='active').first()
    else:
        # For anonymous users, use session ID
        session_id = session.get('session_id')
        if not session_id:
            session_id = str(uuid.uuid4())
            session['session_id'] = session_id
        cart = Cart.query.filter_by(user_id=session_id, status='active').first()
    
    # Create new cart if none exists
    if not cart:
        user_id = current_user.id if current_user.is_authenticated else session.get('session_id')
        cart = Cart(user_id=user_id)
        db.session.add(cart)
        db.session.commit()
    
    # Get items with their products
    items_with_products = []
    for item in cart.items:
        product = Product.query.get(item.product_id)
        if product:
            items_with_products.append((item, product))
    
    # Calculate total price
    total = cart.get_total()
    
    return render_template('cart/view.html', cart=cart, items=items_with_products, total=total)

@app.route('/cart/add/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    """Add a product to the cart"""
    product = Product.query.get_or_404(product_id)
    
    # Don't allow adding deleted products
    if product.is_deleted:
        flash("Product not available", "danger")
        return redirect(url_for('list_products'))
    
    # Check stock
    requested_quantity = int(request.form.get('quantity', 1))
    if requested_quantity <= 0:
        flash("Please enter a valid quantity", "danger")
        return redirect(url_for('get_product', product_id=product_id))
    
    if requested_quantity > product.stock:
        flash(f"Sorry, only {product.stock} items available", "warning")
        requested_quantity = product.stock  # Limit to available stock
    
    # Get or create cart
    if current_user.is_authenticated:
        user_id = current_user.id
    else:
        # For anonymous users, use session ID
        if not session.get('session_id'):
            session['session_id'] = str(uuid.uuid4())
        user_id = session.get('session_id')
    
    cart = Cart.query.filter_by(user_id=user_id, status='active').first()
    
    if not cart:
        cart = Cart(user_id=user_id)
        db.session.add(cart)
        db.session.commit()
    
    # Check if product is already in cart
    cart_item = CartItem.query.filter_by(cart_id=cart.id, product_id=product.id).first()
    
    try:
        if cart_item:
            # Update quantity
            new_quantity = cart_item.quantity + requested_quantity
            if new_quantity > product.stock:
                flash(f"Cart quantity limited to available stock ({product.stock})", "warning")
                new_quantity = product.stock
            
            cart_item.quantity = new_quantity
        else:
            # Create new cart item
            cart_item = CartItem(
                cart_id=cart.id,
                product_id=product.id,
                quantity=requested_quantity,
                price=product.price
            )
            db.session.add(cart_item)
        
        db.session.commit()
        flash(f"{product.name} added to your cart", "success")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding to cart: {str(e)}")
        flash("There was an error adding this item to your cart", "danger")
    
    return redirect(url_for('view_cart'))

@app.route('/cart/update/<int:item_id>', methods=['POST'])
def update_cart_item(item_id):
    """Update cart item quantity"""
    cart_item = CartItem.query.get_or_404(item_id)
    
    # Check cart ownership
    if current_user.is_authenticated:
        user_id = current_user.id
    else:
        user_id = session.get('session_id')
    
    cart = Cart.query.get(cart_item.cart_id)
    if not cart or str(cart.user_id) != str(user_id):
        flash("Item not found in your cart", "danger")
        return redirect(url_for('view_cart'))
    
    try:
        # Update quantity
        new_quantity = int(request.form.get('quantity', 1))
        if new_quantity <= 0:
            return redirect(url_for('remove_from_cart', item_id=item_id))
        
        # Check stock
        product = Product.query.get(cart_item.product_id)
        if not product:
            flash("Product not found", "danger")
            return redirect(url_for('view_cart'))
        
        if new_quantity > product.stock:
            flash(f"Quantity limited to available stock ({product.stock})", "warning")
            new_quantity = product.stock
        
        cart_item.quantity = new_quantity
        db.session.commit()
        
        flash("Cart updated", "success")
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating cart: {str(e)}")
        flash("There was an error updating your cart", "danger")
    
    return redirect(url_for('view_cart'))

@app.route('/cart/remove/<int:item_id>', methods=['POST'])
def remove_from_cart(item_id):
    """Remove item from cart"""
    cart_item = CartItem.query.get_or_404(item_id)
    
    # Check cart ownership
    if current_user.is_authenticated:
        user_id = current_user.id
    else:
        user_id = session.get('session_id')
    
    cart = Cart.query.get(cart_item.cart_id)
    if not cart or str(cart.user_id) != str(user_id):
        flash("Item not found in your cart", "danger")
        return redirect(url_for('view_cart'))
    
    try:
        product_name = cart_item.product.name if cart_item.product else "Item"
        db.session.delete(cart_item)
        db.session.commit()
        
        flash(f"{product_name} removed from your cart", "success")
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error removing from cart: {str(e)}")
        flash("There was an error updating your cart", "danger")
    
    return redirect(url_for('view_cart'))

@app.route('/cart/clear', methods=['POST'])
def clear_cart():
    """Remove all items from cart"""
    if current_user.is_authenticated:
        user_id = current_user.id
    else:
        user_id = session.get('session_id')
        if not user_id:
            flash("Your cart is already empty", "info")
            return redirect(url_for('view_cart'))
    
    cart = Cart.query.filter_by(user_id=user_id, status='active').first()
    if not cart:
        flash("Your cart is already empty", "info")
        return redirect(url_for('view_cart'))
    
    try:
        # Delete all cart items
        for item in cart.items:
            db.session.delete(item)
        
        db.session.commit()
        flash("Your cart has been emptied", "success")
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error clearing cart: {str(e)}")
        flash("There was an error updating your cart", "danger")
    
    return redirect(url_for('view_cart'))

# Order Routes
@app.route('/checkout', methods=['GET'])
@login_required
def checkout():
    """Checkout page for creating an order"""
    # Get user's active cart
    cart = Cart.query.filter_by(user_id=current_user.id, status='active').first()
    
    if not cart or not cart.items:
        flash("Your cart is empty", "warning")
        return redirect(url_for('view_cart'))
    
    # Get items with their products
    items_with_products = []
    for item in cart.items:
        product = Product.query.get(item.product_id)
        if product:
            # Check stock availability
            if item.quantity > product.stock:
                flash(f"Not enough stock for {product.name}. Only {product.stock} available.", "warning")
                return redirect(url_for('view_cart'))
            
            items_with_products.append((item, product))
    
    if not items_with_products:
        flash("Your cart contains unavailable products", "warning")
        return redirect(url_for('view_cart'))
    
    # Calculate total price
    total = cart.get_total()
    
    # Get user's addresses and contacts for convenience
    shipping_addresses = []
    contact_info = []
    
    # These would normally come from the database
    # But for now, we'll leave them empty as those models aren't fully implemented yet
    
    return render_template(
        'order/checkout.html', 
        cart=cart, 
        items=items_with_products, 
        total=total,
        shipping_addresses=shipping_addresses,
        contact_info=contact_info
    )

@app.route('/order/create', methods=['POST'])
@login_required
def create_order():
    """Create a new order from the cart"""
    # Get user's active cart
    cart = Cart.query.filter_by(user_id=current_user.id, status='active').first()
    
    if not cart or not cart.items:
        flash("Your cart is empty", "warning")
        return redirect(url_for('view_cart'))
    
    # Validate required fields
    if not request.form.get('shipping_address'):
        flash("Shipping address is required", "danger")
        return redirect(url_for('checkout'))
    
    if not request.form.get('contact_info'):
        flash("Contact information is required", "danger")
        return redirect(url_for('checkout'))
    
    # Check if billing address is the same as shipping
    if request.form.get('same_billing_address') in ['on', True, 'true', 'True', 1, '1']:
        billing_address = request.form.get('shipping_address')
    else:
        billing_address = request.form.get('billing_address')
        if not billing_address:
            flash("Billing address is required", "danger")
            return redirect(url_for('checkout'))
    
    # Calculate total and verify stock one more time
    total = Decimal('0.0')
    order_items = []
    
    for item in cart.items:
        product = Product.query.get(item.product_id)
        if not product:
            flash(f"One of the products in your cart is no longer available", "danger")
            return redirect(url_for('view_cart'))
        
        if product.stock < item.quantity:
            flash(f"Not enough stock for {product.name}. Only {product.stock} available.", "warning")
            return redirect(url_for('view_cart'))
        
        # Calculate item total
        item_total = item.price * item.quantity
        total += item_total
        
        # Prepare order item
        order_item = {
            'product_id': product.id,
            'quantity': item.quantity,
            'price': float(item.price),
            'total': float(item_total)
        }
        order_items.append(order_item)
    
    try:
        # Create order
        order = Order(
            user_id=current_user.id,
            cart_id=cart.id,
            total=float(total),
            status='pending',
            shipping_address=request.form.get('shipping_address'),
            billing_address=billing_address,
            contact_info=request.form.get('contact_info')
        )
        
        db.session.add(order)
        db.session.flush()  # Get the order ID
        
        # Create order items
        for item_data in order_items:
            order_item = OrderItem(
                order_id=order.id,
                product_id=item_data['product_id'],
                quantity=item_data['quantity'],
                price=item_data['price'],
                total=item_data['total']
            )
            db.session.add(order_item)
            
            # Update product stock
            product = Product.query.get(item_data['product_id'])
            product.stock -= item_data['quantity']
        
        # Update cart status
        cart.status = 'completed'
        
        db.session.commit()
        
        # Redirect to order confirmation
        return redirect(url_for('get_order', order_id=order.id))
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating order: {str(e)}")
        flash(f"There was an error processing your order: {str(e)}", "danger")
        return redirect(url_for('checkout'))

@app.route('/orders', methods=['GET'])
@login_required
def list_orders():
    """List all orders for the current user"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get all orders for the current user
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('order/history.html', orders=orders)

@app.route('/orders/<int:order_id>', methods=['GET'])
@login_required
def get_order(order_id):
    """View details of a specific order"""
    order = Order.query.get_or_404(order_id)
    
    # Check if the order belongs to the current user
    if order.user_id != current_user.id and not current_user.has_role('admin'):
        flash("You don't have permission to view this order", "danger")
        return redirect(url_for('list_orders'))
    
    return render_template('order/confirmation.html', order=order)

@app.route('/order/<int:order_id>/cancel', methods=['POST'])
@login_required
def cancel_order(order_id):
    """Cancel an order"""
    order = Order.query.get_or_404(order_id)
    
    # Check if the order belongs to the current user
    if order.user_id != current_user.id and not current_user.has_role('admin'):
        flash("You don't have permission to cancel this order", "danger")
        return redirect(url_for('list_orders'))
    
    # Check if the order can be canceled
    if order.status not in ['pending', 'paid']:
        flash("This order cannot be canceled because it has already been shipped or delivered", "danger")
        return redirect(url_for('get_order', order_id=order.id))
    
    try:
        # Update order status
        order.status = 'canceled'
        
        # Restore product stock
        for item in order.items:
            product = Product.query.get(item.product_id)
            if product:
                product.stock += item.quantity
        
        db.session.commit()
        flash("Your order has been canceled", "success")
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error canceling order: {str(e)}")
        flash(f"There was an error canceling your order: {str(e)}", "danger")
    
    return redirect(url_for('get_order', order_id=order.id))

# REST API Endpoints (JWT Protected)
@app.route('/api/products', methods=['GET'])
@jwt_required()
def api_list_products():
    """API endpoint to list all active products (JWT protected)"""
    # Get query parameters for filtering and pagination
    search = request.args.get('search', '')
    sort_by = request.args.get('sort', 'name')
    sort_order = request.args.get('order', 'asc')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # Build query
    query = Product.query.filter_by(is_deleted=False)
    
    # Apply search if provided
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Product.name.ilike(search_term),
                Product.description.ilike(search_term),
                Product.sku.ilike(search_term),
                Product.barcode.ilike(search_term)
            )
        )
    
    # Apply sorting
    if sort_by == 'price':
        order_col = Product.price
    elif sort_by == 'name':
        order_col = Product.name
    elif sort_by == 'created_at':
        order_col = Product.created_at
    else:
        order_col = Product.name
    
    if sort_order == 'desc':
        query = query.order_by(order_col.desc())
    else:
        query = query.order_by(order_col.asc())
    
    # Paginate results
    products_page = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Format response
    products = [
        {
            'id': p.id,
            'name': p.name,
            'sku': p.sku,
            'barcode': p.barcode,
            'description': p.description,
            'price': float(p.price),
            'stock': p.stock,
            'created_at': p.created_at.isoformat() if p.created_at else None,
            'updated_at': p.updated_at.isoformat() if p.updated_at else None
        }
        for p in products_page.items
    ]
    
    return jsonify({
        'products': products,
        'page': products_page.page,
        'pages': products_page.pages,
        'total': products_page.total,
        'per_page': products_page.per_page
    }), 200

@app.route('/api/products/<int:product_id>', methods=['GET'])
@jwt_required()
def api_get_product(product_id):
    """API endpoint to get a specific product (JWT protected)"""
    product = Product.query.get_or_404(product_id)
    
    # Check if product is deleted
    if product.is_deleted:
        # Get current user from JWT
        identity = get_jwt_identity()
        user = User.query.get(identity)
        
        # Only admins can see deleted products
        if not user or not user.has_role('admin'):
            return jsonify({"message": "Product not found"}), 404
    
    # Format response
    product_data = {
        'id': product.id,
        'name': product.name,
        'sku': product.sku,
        'barcode': product.barcode,
        'description': product.description,
        'price': float(product.price),
        'stock': product.stock,
        'is_deleted': product.is_deleted,
        'created_at': product.created_at.isoformat() if product.created_at else None,
        'updated_at': product.updated_at.isoformat() if product.updated_at else None
    }
    
    return jsonify(product_data), 200

@app.route('/api/products', methods=['POST'])
@jwt_role_required('admin')
def api_create_product():
    """API endpoint to create a new product (JWT protected, admin only)"""
    # Check if required fields are provided
    if not request.is_json:
        return jsonify({"message": "Missing JSON in request"}), 400
    
    required_fields = ['name', 'sku', 'barcode', 'price']
    for field in required_fields:
        if field not in request.json:
            return jsonify({"message": f"Missing required field: {field}"}), 400
    
    # Check for duplicate SKU or barcode
    existing_product = Product.query.filter(
        (Product.sku == request.json.get('sku')) | 
        (Product.barcode == request.json.get('barcode'))
    ).first()
    
    if existing_product:
        return jsonify({"message": "A product with this SKU or barcode already exists"}), 409
    
    try:
        # Create new product
        new_product = Product(
            name=request.json.get('name'),
            sku=request.json.get('sku'),
            barcode=request.json.get('barcode'),
            description=request.json.get('description', ''),
            price=float(request.json.get('price')),
            stock=int(request.json.get('stock', 0))
        )
        
        db.session.add(new_product)
        db.session.commit()
        
        # Format response
        product_data = {
            'id': new_product.id,
            'name': new_product.name,
            'sku': new_product.sku,
            'barcode': new_product.barcode,
            'description': new_product.description,
            'price': float(new_product.price),
            'stock': new_product.stock,
            'created_at': new_product.created_at.isoformat() if new_product.created_at else None
        }
        
        return jsonify(product_data), 201
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating product: {str(e)}")
        return jsonify({"message": f"Error creating product: {str(e)}"}), 500

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@jwt_role_required('admin')
def api_update_product(product_id):
    """API endpoint to update a product (JWT protected, admin only)"""
    # Check if required fields are provided
    if not request.is_json:
        return jsonify({"message": "Missing JSON in request"}), 400
    
    product = Product.query.get_or_404(product_id)
    
    # Check for duplicate SKU or barcode (excluding this product)
    if 'sku' in request.json or 'barcode' in request.json:
        filters = []
        if 'sku' in request.json and request.json['sku'] != product.sku:
            filters.append(Product.sku == request.json['sku'])
        if 'barcode' in request.json and request.json['barcode'] != product.barcode:
            filters.append(Product.barcode == request.json['barcode'])
        
        if filters:
            existing_product = Product.query.filter(
                db.or_(*filters),
                Product.id != product_id
            ).first()
            
            if existing_product:
                return jsonify({"message": "Another product with this SKU or barcode already exists"}), 409
    
    try:
        # Update product fields if provided
        if 'name' in request.json:
            product.name = request.json['name']
        if 'sku' in request.json:
            product.sku = request.json['sku']
        if 'barcode' in request.json:
            product.barcode = request.json['barcode']
        if 'description' in request.json:
            product.description = request.json['description']
        if 'price' in request.json:
            product.price = float(request.json['price'])
        if 'stock' in request.json:
            product.stock = int(request.json['stock'])
        if 'is_deleted' in request.json:
            product.is_deleted = bool(request.json['is_deleted'])
        
        product.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Format response
        product_data = {
            'id': product.id,
            'name': product.name,
            'sku': product.sku,
            'barcode': product.barcode,
            'description': product.description,
            'price': float(product.price),
            'stock': product.stock,
            'is_deleted': product.is_deleted,
            'created_at': product.created_at.isoformat() if product.created_at else None,
            'updated_at': product.updated_at.isoformat() if product.updated_at else None
        }
        
        return jsonify(product_data), 200
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating product: {str(e)}")
        return jsonify({"message": f"Error updating product: {str(e)}"}), 500

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@jwt_role_required('admin')
def api_delete_product(product_id):
    """API endpoint to delete a product (JWT protected, admin only)"""
    product = Product.query.get_or_404(product_id)
    
    try:
        # Soft delete by setting is_deleted flag
        product.is_deleted = True
        product.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({"message": "Product deleted successfully"}), 200
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting product: {str(e)}")
        return jsonify({"message": f"Error deleting product: {str(e)}"}), 500

# Create database tables and initialize with sample data
def initialize_database():
    """Initialize database with required data"""
    with app.app_context():
        db.create_all()
        
        # Add roles if they don't exist
        roles = {
            'admin': 'Administrator with full access',
            'user': 'Regular user with limited access',
            'manager': 'Store manager with product management access'
        }
        
        for role_name, description in roles.items():
            if not Role.query.filter_by(name=role_name).first():
                role = Role(name=role_name, description=description)
                db.session.add(role)
        
        # Add permissions if they don't exist
        permissions = {
            'user.view': 'View user details',
            'user.edit': 'Edit user details',
            'user.delete': 'Delete users',
            'product.view': 'View products',
            'product.create': 'Create products',
            'product.edit': 'Edit products',
            'product.delete': 'Delete products',
            'order.view': 'View orders',
            'order.create': 'Create orders',
            'order.edit': 'Edit orders',
            'order.delete': 'Delete orders',
        }
        
        for perm_code, description in permissions.items():
            if not Permission.query.filter_by(code=perm_code).first():
                permission = Permission(code=perm_code, description=description)
                db.session.add(permission)
        
        # Create admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                email='admin@example.com',
                first_name='Admin',
                last_name='User',
                is_active=True
            )
            admin_user.set_password('admin123')
            
            # Add admin role
            admin_role = Role.query.filter_by(name='admin').first()
            if admin_role:
                admin_user.roles.append(admin_role)
            
            db.session.add(admin_user)
        
        # Add sample products if there are none
        if Product.query.count() == 0:
            sample_products = [
                {
                    'name': 'Smartphone X1',
                    'sku': 'PHONE-X1',
                    'barcode': '1234567890123',
                    'description': 'Latest model smartphone with 6.5" OLED display, 128GB storage, and triple camera system.',
                    'price': 599.99,
                    'stock': 50
                },
                {
                    'name': 'Laptop Pro 15',
                    'sku': 'LAPTOP-P15',
                    'barcode': '1234567890124',
                    'description': 'Professional laptop with 15" display, 16GB RAM, 512GB SSD, and dedicated graphics card.',
                    'price': 1299.99,
                    'stock': 25
                },
                {
                    'name': 'Wireless Headphones',
                    'sku': 'AUDIO-WH1',
                    'barcode': '1234567890125',
                    'description': 'Premium wireless headphones with noise cancellation, 30-hour battery life, and high-definition audio.',
                    'price': 199.99,
                    'stock': 100
                },
                {
                    'name': 'Smart Watch',
                    'sku': 'WATCH-SW1',
                    'barcode': '1234567890126',
                    'description': 'Fitness and health tracking smartwatch with heart rate monitor, GPS, and 7-day battery life.',
                    'price': 149.99,
                    'stock': 75
                },
                {
                    'name': 'Bluetooth Speaker',
                    'sku': 'AUDIO-BS1',
                    'barcode': '1234567890127',
                    'description': 'Portable Bluetooth speaker with 360° sound, waterproof design, and 12-hour battery life.',
                    'price': 79.99,
                    'stock': 120
                },
                {
                    'name': 'Tablet Pro',
                    'sku': 'TABLET-P1',
                    'barcode': '1234567890128',
                    'description': '10.5" tablet with high-resolution display, 64GB storage, and all-day battery life.',
                    'price': 349.99,
                    'stock': 40
                },
                {
                    'name': 'Wireless Charger',
                    'sku': 'ACC-WC1',
                    'barcode': '1234567890129',
                    'description': 'Fast wireless charging pad compatible with most modern smartphones and accessories.',
                    'price': 29.99,
                    'stock': 150
                },
                {
                    'name': 'Gaming Console',
                    'sku': 'GAME-C1',
                    'barcode': '1234567890130',
                    'description': 'Next-generation gaming console with 1TB storage, 4K graphics, and includes one controller.',
                    'price': 499.99,
                    'stock': 30
                }
            ]
            
            for product_data in sample_products:
                product = Product(
                    name=product_data['name'],
                    sku=product_data['sku'],
                    barcode=product_data['barcode'],
                    description=product_data['description'],
                    price=product_data['price'],
                    stock=product_data['stock']
                )
                db.session.add(product)
            
            logger.info("Added sample products to the database")
        
        db.session.commit()
        logger.info("Database initialized with roles, permissions, admin user, and products")

# Run the initialization function
initialize_database()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)