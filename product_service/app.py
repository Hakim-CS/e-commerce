import os
import logging
import requests
from datetime import timedelta

from flask import Flask, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Define user service URL
USER_SERVICE_URL = os.environ.get("USER_SERVICE_URL", "http://localhost:8000")

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
    SECRET_KEY=os.environ.get("SESSION_SECRET", "super-secret-product-service-key"),
    SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/product_service"),
    SQLALCHEMY_ENGINE_OPTIONS={
        "pool_recycle": 300,
        "pool_pre_ping": True,
    },
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)

# Authentication middleware to check if user is logged in
@app.before_request
def check_authentication():
    # Skip auth check for static files and login route
    if request.path.startswith('/static') or request.path == '/login':
        return
    
    # Check if user is logged in
    if 'user_id' not in session:
        # If token is in the session, validate it
        token = session.get('access_token')
        if token:
            try:
                headers = {'Authorization': f'Bearer {token}'}
                response = requests.get(f"{USER_SERVICE_URL}/auth/checkLogin", headers=headers)
                if response.status_code == 200 and response.json().get('authenticated'):
                    # Token is valid, user is authenticated
                    return
            except Exception as e:
                logger.error(f"Error checking token: {e}")
        
        # Token is invalid or not present, redirect to login
        return redirect(f"{USER_SERVICE_URL}/auth/login")

# Import models to ensure they're registered with SQLAlchemy
with app.app_context():
    import models
    from routes import product, cart, order
    
    # Register blueprints
    app.register_blueprint(product.bp)
    app.register_blueprint(cart.bp)
    app.register_blueprint(order.bp)
    
    # Create all tables
    db.create_all()
    
    # Initialize sample products if database is empty
    from models import Product
    if Product.query.count() == 0:
        try:
            sample_products = [
                {
                    'name': 'Smartphone X Pro',
                    'sku': 'SPH-X100',
                    'barcode': '8901234567890',
                    'description': 'Latest flagship smartphone with advanced camera features.',
                    'price': 799.99,
                    'stock': 50
                },
                {
                    'name': 'Wireless Earbuds',
                    'sku': 'AUD-E200',
                    'barcode': '8901234567891',
                    'description': 'Premium wireless earbuds with active noise cancellation.',
                    'price': 149.99,
                    'stock': 100
                },
                {
                    'name': 'Smart Watch Series 5',
                    'sku': 'WCH-S500',
                    'barcode': '8901234567892',
                    'description': 'Fitness tracker and smartwatch with heart rate monitoring.',
                    'price': 249.99,
                    'stock': 75
                },
                {
                    'name': 'Laptop Pro 15',
                    'sku': 'LPT-P150',
                    'barcode': '8901234567893',
                    'description': 'Powerful laptop for professionals with high-resolution display.',
                    'price': 1299.99,
                    'stock': 25
                },
                {
                    'name': 'Wireless Charging Pad',
                    'sku': 'ACC-C100',
                    'barcode': '8901234567894',
                    'description': 'Fast wireless charging pad compatible with most devices.',
                    'price': 39.99,
                    'stock': 150
                }
            ]
            
            for product_data in sample_products:
                product = Product(**product_data)
                db.session.add(product)
            
            db.session.commit()
            logger.info("Added sample products to database")
        except Exception as e:
            logger.error(f"Error adding sample products: {e}")
            db.session.rollback()
