import json
import requests
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session, current_app
from sqlalchemy.exc import SQLAlchemyError

from app import db, USER_SERVICE_URL
from models import Cart, CartItem, Order, OrderItem, Product
from utils.auth import login_required, permission_required, admin_required

bp = Blueprint('order', __name__, url_prefix='/orders')

@bp.route('/', methods=['GET'])
@login_required
def list_orders():
    """Get all orders for the current user"""
    user_id = session.get('user_id')
    
    # Get query parameters for pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get all orders for the user with pagination
    orders = Order.query.filter_by(user_id=user_id)\
        .order_by(Order.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    if request.headers.get('Accept') == 'application/json' or request.is_json:
        return jsonify({
            "orders": [order.to_dict() for order in orders.items],
            "pagination": {
                "page": orders.page,
                "per_page": orders.per_page,
                "total": orders.total,
                "pages": orders.pages
            }
        })
    else:
        return render_template('order/history.html', orders=orders)

@bp.route('/<int:order_id>', methods=['GET'])
@login_required
def get_order(order_id):
    """Get details of a specific order"""
    user_id = session.get('user_id')
    is_admin = session.get('is_admin', False)
    
    # Get the order
    order = Order.query.get_or_404(order_id)
    
    # Check if the order belongs to the user or user is admin
    if order.user_id != user_id and not is_admin:
        if request.is_json:
            return jsonify({"error": "Unauthorized access to order"}), 403
        else:
            flash("You don't have permission to view this order", "danger")
            return redirect(url_for('order.list_orders'))
    
    if request.headers.get('Accept') == 'application/json' or request.is_json:
        return jsonify(order.to_dict())
    else:
        return render_template('order/confirmation.html', order=order)

@bp.route('/', methods=['POST'])
@login_required
def create_order():
    """Create a new order from the current cart"""
    user_id = session.get('user_id')
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    shipping_address = data.get('shipping_address')
    billing_address = data.get('billing_address')
    contact_info = data.get('contact_info')
    
    # Validate input
    if not shipping_address:
        if request.is_json:
            return jsonify({"error": "Shipping address is required"}), 400
        else:
            flash("Shipping address is required", "danger")
            return redirect(url_for('order.checkout'))
    
    # Get user's active cart
    cart = Cart.query.filter_by(user_id=user_id, status='active').first()
    
    if not cart or not cart.items:
        if request.is_json:
            return jsonify({"error": "Cart is empty"}), 400
        else:
            flash("Your cart is empty", "warning")
            return redirect(url_for('cart.view_cart'))
    
    try:
        # Validate stock for all items in cart
        for item in cart.items:
            product = Product.query.get(item.product_id)
            if product.stock < item.quantity:
                if request.is_json:
                    return jsonify({"error": f"Not enough stock for {product.name}. Only {product.stock} available."}), 400
                else:
                    flash(f"Not enough stock for {product.name}. Only {product.stock} available.", "danger")
                    return redirect(url_for('cart.view_cart'))
        
        # Calculate total
        total = cart.get_total()
        
        # Create order
        order = Order(
            user_id=user_id,
            cart_id=cart.id,
            total=total,
            status='pending',
            shipping_address=shipping_address,
            billing_address=billing_address or shipping_address,  # Use shipping as billing if not provided
            contact_info=contact_info
        )
        db.session.add(order)
        
        # Create order items
        for cart_item in cart.items:
            order_item = OrderItem(
                order_id=order.id,
                product_id=cart_item.product_id,
                quantity=cart_item.quantity,
                price=cart_item.price,
                total=cart_item.total
            )
            db.session.add(order_item)
            
            # Reduce product stock
            product = Product.query.get(cart_item.product_id)
            product.stock -= cart_item.quantity
        
        # Mark cart as completed
        cart.status = 'completed'
        
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                "message": "Order created successfully",
                "order": order.to_dict()
            }), 201
        else:
            flash("Order placed successfully! Thank you for your purchase.", "success")
            return redirect(url_for('order.get_order', order_id=order.id))
    
    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating order: {str(e)}")
        
        if request.is_json:
            return jsonify({"error": "Failed to create order"}), 500
        else:
            flash("Failed to create order. Please try again.", "danger")
            return redirect(url_for('cart.view_cart'))

@bp.route('/<int:order_id>/status', methods=['PUT', 'POST'])
@permission_required('orders.update')
def update_order_status(order_id):
    """Update the status of an order (admin only)"""
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    status = data.get('status')
    
    # Validate input
    valid_statuses = ['pending', 'paid', 'shipped', 'delivered', 'canceled']
    if not status or status not in valid_statuses:
        if request.is_json:
            return jsonify({"error": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"}), 400
        else:
            flash(f"Invalid status. Must be one of: {', '.join(valid_statuses)}", "danger")
            return redirect(url_for('order.admin_orders'))
    
    try:
        # Get the order
        order = Order.query.get_or_404(order_id)
        
        # Update status
        order.status = status
        
        # If canceling the order, restore product stock
        if status == 'canceled' and order.status != 'canceled':
            for order_item in order.items:
                product = Product.query.get(order_item.product_id)
                product.stock += order_item.quantity
        
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                "message": f"Order status updated to {status}",
                "order": order.to_dict()
            })
        else:
            flash(f"Order status updated to {status}", "success")
            return redirect(url_for('order.admin_view_order', order_id=order_id))
    
    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating order status: {str(e)}")
        
        if request.is_json:
            return jsonify({"error": "Failed to update order status"}), 500
        else:
            flash("Failed to update order status", "danger")
            return redirect(url_for('order.admin_view_order', order_id=order_id))

@bp.route('/<int:order_id>/status', methods=['GET'])
@login_required
def check_order_status(order_id):
    """Check the status of an order"""
    user_id = session.get('user_id')
    is_admin = session.get('is_admin', False)
    
    # Get the order
    order = Order.query.get_or_404(order_id)
    
    # Check if the order belongs to the user or user is admin
    if order.user_id != user_id and not is_admin:
        if request.is_json:
            return jsonify({"error": "Unauthorized access to order"}), 403
        else:
            flash("You don't have permission to view this order", "danger")
            return redirect(url_for('order.list_orders'))
    
    if request.headers.get('Accept') == 'application/json' or request.is_json:
        return jsonify({
            "order_id": order.id,
            "status": order.status,
            "updated_at": order.updated_at.isoformat() if order.updated_at else None
        })
    else:
        flash(f"Order status: {order.status}", "info")
        return redirect(url_for('order.get_order', order_id=order_id))

@bp.route('/checkout', methods=['GET'])
@login_required
def checkout():
    """Display checkout page"""
    user_id = session.get('user_id')
    
    # Get user's active cart
    cart = Cart.query.filter_by(user_id=user_id, status='active').first()
    
    if not cart or not cart.items:
        flash("Your cart is empty", "warning")
        return redirect(url_for('cart.view_cart'))
    
    # Get user's addresses and contacts from user service
    shipping_addresses = []
    contact_info = []
    
    # Get user token from session
    token = session.get('access_token')
    
    if token:
        # Get addresses
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get(f"{USER_SERVICE_URL}/address", headers=headers)
            if response.status_code == 200:
                addresses_data = response.json()
                if 'addresses' in addresses_data:
                    shipping_addresses = addresses_data['addresses']
        except Exception as e:
            current_app.logger.error(f"Error fetching addresses: {str(e)}")
        
        # Get contacts
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get(f"{USER_SERVICE_URL}/address/contact", headers=headers)
            if response.status_code == 200:
                contacts_data = response.json()
                if 'contacts' in contacts_data:
                    contact_info = contacts_data['contacts']
        except Exception as e:
            current_app.logger.error(f"Error fetching contacts: {str(e)}")
    
    # Get cart items with product info
    items = db.session.query(CartItem, Product)\
        .join(Product, CartItem.product_id == Product.id)\
        .filter(CartItem.cart_id == cart.id)\
        .all()
    
    # Calculate total
    total = cart.get_total()
    
    return render_template(
        'order/checkout.html',
        cart=cart,
        items=items,
        total=total,
        shipping_addresses=shipping_addresses,
        contact_info=contact_info
    )

@bp.route('/admin', methods=['GET'])
@admin_required
def admin_orders():
    """Admin view for managing orders"""
    # Get query parameters for filtering and pagination
    status = request.args.get('status', 'all')
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # Build query
    query = Order.query
    
    # Apply status filter
    if status != 'all':
        query = query.filter_by(status=status)
    
    # Apply search if provided (search by order ID)
    if search:
        try:
            order_id = int(search)
            query = query.filter_by(id=order_id)
        except ValueError:
            # If search is not a valid order ID, return no results
            query = query.filter_by(id=0)
    
    # Order by created_at descending (newest first)
    query = query.order_by(Order.created_at.desc())
    
    # Paginate results
    orders = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template(
        'admin/orders.html',
        orders=orders,
        status=status,
        search=search
    )

@bp.route('/admin/<int:order_id>', methods=['GET'])
@admin_required
def admin_view_order(order_id):
    """Admin view for order details"""
    order = Order.query.get_or_404(order_id)
    
    # Get user info from user service if possible
    user_info = None
    token = session.get('access_token')
    
    if token:
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get(f"{USER_SERVICE_URL}/user/{order.user_id}", headers=headers)
            if response.status_code == 200:
                user_info = response.json()
        except Exception as e:
            current_app.logger.error(f"Error fetching user info: {str(e)}")
    
    return render_template('admin/order_detail.html', order=order, user_info=user_info)
