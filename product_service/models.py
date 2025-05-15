from datetime import datetime
from sqlalchemy import Enum
from app import db

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
            'total': float(self.get_total())
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
