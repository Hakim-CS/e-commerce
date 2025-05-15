from datetime import datetime
from flask_login import UserMixin
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum

db = SQLAlchemy()

# Association tables for many-to-many relationships
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('created_at', db.DateTime, default=datetime.utcnow)
)

role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'), primary_key=True),
    db.Column('created_at', db.DateTime, default=datetime.utcnow)
)

class User(UserMixin, db.Model):
    """User model for authentication and profile data"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    roles = db.relationship('Role', secondary=user_roles, lazy='subquery',
                        backref=db.backref('users', lazy=True))
    addresses = db.relationship('Address', back_populates='user', cascade='all, delete-orphan')
    contacts = db.relationship('Contact', back_populates='user', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'
        
    def set_password(self, password):
        """Set user password"""
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """Check if password is correct"""
        return check_password_hash(self.password_hash, password)
        
    def has_role(self, role_name):
        """Check if user has a specific role"""
        return any(role.name == role_name for role in self.roles)
        
    def has_permission(self, permission_code):
        """Check if user has a specific permission"""
        for role in self.roles:
            for permission in role.permissions:
                if permission.code == permission_code:
                    return True
        return False
    
    def to_dict(self):
        """Convert user to dictionary (safe version for API responses)"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'roles': [role.name for role in self.roles]
        }

class Role(db.Model):
    """Role model for user permissions grouping"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(256))
    permissions = db.relationship('Permission', secondary=role_permissions, lazy='subquery',
                                 backref=db.backref('roles', lazy=True))
    
    def __repr__(self):
        return f'<Role {self.name}>'
    
    def to_dict(self):
        """Convert role to dictionary for API responses"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'permissions': [permission.to_dict() for permission in self.permissions]
        }

class Permission(db.Model):
    """Permission model for granular access control"""
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(256))
    
    def __repr__(self):
        return f'<Permission {self.code}>'
    
    def to_dict(self):
        """Convert permission to dictionary for API responses"""
        return {
            'id': self.id,
            'code': self.code,
            'description': self.description
        }

class Address(db.Model):
    """Address model for user addresses"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    address_type = db.Column(db.String(20), nullable=False)  # 'Home', 'Work', etc.
    street = db.Column(db.String(128), nullable=False)
    city = db.Column(db.String(64), nullable=False)
    state = db.Column(db.String(64))
    postal_code = db.Column(db.String(20), nullable=False)
    country = db.Column(db.String(64), nullable=False)
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', back_populates='addresses')
    
    def __repr__(self):
        return f'<Address {self.id}: {self.address_type} for user {self.user_id}>'
    
    def to_dict(self):
        """Convert address to dictionary for API responses"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'address_type': self.address_type,
            'street': self.street,
            'city': self.city,
            'state': self.state,
            'postal_code': self.postal_code,
            'country': self.country,
            'is_default': self.is_default,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Contact(db.Model):
    """Contact model for user contact information"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_type = db.Column(db.String(20), nullable=False)  # 'Home', 'Work', etc.
    phone_number = db.Column(db.String(20))
    email = db.Column(db.String(120))
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', back_populates='contacts')
    
    def __repr__(self):
        return f'<Contact {self.id}: {self.contact_type} for user {self.user_id}>'
    
    def to_dict(self):
        """Convert contact to dictionary for API responses"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'contact_type': self.contact_type,
            'phone_number': self.phone_number,
            'email': self.email,
            'is_default': self.is_default,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Token(db.Model):
    """Model for tracking refresh tokens"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    jti = db.Column(db.String(36), nullable=False, unique=True)  # JWT ID
    token_type = db.Column(db.String(10), nullable=False)  # 'access' or 'refresh'
    revoked = db.Column(db.Boolean, default=False)
    expires = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Token {self.id} ({self.token_type}) for user {self.user_id}>'

# Product and Order Models
class Product(db.Model):
    """Product model representing items for sale"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    sku = db.Column(db.String(64), unique=True, nullable=False)
    barcode = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    stock = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)
    
    # Relationships
    cart_items = db.relationship('CartItem', back_populates='product', cascade='all, delete-orphan')
    order_items = db.relationship('OrderItem', back_populates='product')
    
    def __repr__(self):
        return f'<Product {self.id}: {self.name}>'
    
    def to_dict(self):
        """Convert product to dictionary for API responses"""
        return {
            'id': self.id,
            'name': self.name,
            'sku': self.sku,
            'barcode': self.barcode,
            'description': self.description,
            'price': float(self.price),
            'stock': self.stock,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'is_deleted': self.is_deleted
        }

class Cart(db.Model):
    """Shopping cart model"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = db.Column(
        Enum('active', 'completed', 'abandoned', name='cart_status'),
        default='active',
        nullable=False
    )
    
    # Relationships
    items = db.relationship('CartItem', back_populates='cart', cascade='all, delete-orphan')
    orders = db.relationship('Order', back_populates='cart')
    
    def __repr__(self):
        return f'<Cart {self.id} for user {self.user_id}>'
    
    def get_total(self):
        """Calculate total price of all items in cart"""
        return sum(item.total for item in self.items)
    
    def to_dict(self):
        """Convert cart to dictionary for API responses"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'items': [item.to_dict() for item in self.items],
            'total': float(self.get_total()) if self.items else 0
        }

class CartItem(db.Model):
    """Items in a shopping cart"""
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)  # Price at time of adding to cart
    
    # Relationships
    cart = db.relationship('Cart', back_populates='items')
    product = db.relationship('Product', back_populates='cart_items')
    
    @property
    def total(self):
        """Calculate total price for this item (price * quantity)"""
        return self.price * self.quantity
    
    def __repr__(self):
        return f'<CartItem {self.id}: {self.quantity}x Product {self.product_id}>'
    
    def to_dict(self):
        """Convert cart item to dictionary for API responses"""
        return {
            'id': self.id,
            'cart_id': self.cart_id,
            'product_id': self.product_id,
            'product_name': self.product.name if self.product else None,
            'quantity': self.quantity,
            'price': float(self.price),
            'total': float(self.total)
        }

class Order(db.Model):
    """Order model representing completed purchases"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable=False)
    total = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(
        Enum('pending', 'paid', 'shipped', 'delivered', 'canceled', name='order_status'),
        default='pending',
        nullable=False
    )
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Shipping and billing information
    shipping_address = db.Column(db.Text, nullable=True)
    billing_address = db.Column(db.Text, nullable=True)
    contact_info = db.Column(db.Text, nullable=True)
    
    # Relationships
    cart = db.relationship('Cart', back_populates='orders')
    items = db.relationship('OrderItem', back_populates='order', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Order {self.id} for user {self.user_id}, status: {self.status}>'
    
    def to_dict(self):
        """Convert order to dictionary for API responses"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'cart_id': self.cart_id,
            'total': float(self.total),
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'shipping_address': self.shipping_address,
            'billing_address': self.billing_address,
            'contact_info': self.contact_info,
            'items': [item.to_dict() for item in self.items]
        }

class OrderItem(db.Model):
    """Items in an order"""
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)  # Price at time of order
    total = db.Column(db.Numeric(10, 2), nullable=False)  # Total for this item (price * quantity)
    
    # Relationships
    order = db.relationship('Order', back_populates='items')
    product = db.relationship('Product', back_populates='order_items')
    
    def __repr__(self):
        return f'<OrderItem {self.id}: {self.quantity}x Product {self.product_id}>'
    
    def to_dict(self):
        """Convert order item to dictionary for API responses"""
        return {
            'id': self.id,
            'order_id': self.order_id,
            'product_id': self.product_id,
            'product_name': self.product.name if self.product else None,
            'quantity': self.quantity,
            'price': float(self.price),
            'total': float(self.total)
        }