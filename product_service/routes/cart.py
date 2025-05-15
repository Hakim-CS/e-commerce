from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session, current_app
from sqlalchemy.exc import SQLAlchemyError

from app import db
from models import Cart, CartItem, Product
from utils.auth import login_required

bp = Blueprint('cart', __name__, url_prefix='/cart')

def get_user_cart(user_id):
    """Helper function to get or create a user's active cart"""
    # Look for an active cart for this user
    cart = Cart.query.filter_by(user_id=user_id, status='active').first()
    
    # If no active cart found, create a new one
    if not cart:
        cart = Cart(user_id=user_id, status='active')
        db.session.add(cart)
        db.session.commit()
    
    return cart

@bp.route('/', methods=['GET'])
@login_required
def view_cart():
    """View the current user's shopping cart"""
    user_id = session.get('user_id')
    
    # Get user's active cart
    cart = Cart.query.filter_by(user_id=user_id, status='active').first()
    
    # If no active cart exists, return empty cart
    if not cart:
        if request.headers.get('Accept') == 'application/json' or request.is_json:
            return jsonify({
                "cart": {
                    "id": None,
                    "user_id": user_id,
                    "status": "active",
                    "items": [],
                    "total": 0
                }
            })
        else:
            return render_template('cart/view.html', cart=None, items=[], total=0)
    
    # Get cart items with product info
    items = db.session.query(CartItem, Product)\
        .join(Product, CartItem.product_id == Product.id)\
        .filter(CartItem.cart_id == cart.id)\
        .all()
    
    # Calculate total
    total = sum(item.total for item in cart.items)
    
    if request.headers.get('Accept') == 'application/json' or request.is_json:
        return jsonify({
            "cart": cart.to_dict()
        })
    else:
        return render_template('cart/view.html', cart=cart, items=items, total=total)

@bp.route('/items', methods=['POST'])
@login_required
def add_to_cart():
    """Add an item to the shopping cart"""
    user_id = session.get('user_id')
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    product_id = data.get('product_id')
    quantity = int(data.get('quantity', 1))
    
    # Validate input
    if not product_id:
        if request.is_json:
            return jsonify({"error": "Product ID is required"}), 400
        else:
            flash("Product ID is required", "danger")
            return redirect(url_for('product.list_products'))
    
    if quantity < 1:
        if request.is_json:
            return jsonify({"error": "Quantity must be at least 1"}), 400
        else:
            flash("Quantity must be at least 1", "danger")
            return redirect(url_for('product.list_products'))
    
    # Get product
    product = Product.query.get_or_404(product_id)
    
    # Check if product is available
    if product.is_deleted:
        if request.is_json:
            return jsonify({"error": "Product is no longer available"}), 400
        else:
            flash("Product is no longer available", "danger")
            return redirect(url_for('product.list_products'))
    
    # Check stock
    if quantity > product.stock:
        if request.is_json:
            return jsonify({"error": f"Not enough stock. Only {product.stock} available."}), 400
        else:
            flash(f"Not enough stock. Only {product.stock} available.", "warning")
            return redirect(url_for('product.get_product', product_id=product_id))
    
    try:
        # Get or create user's cart
        cart = get_user_cart(user_id)
        
        # Check if product already in cart
        cart_item = CartItem.query.filter_by(cart_id=cart.id, product_id=product_id).first()
        
        if cart_item:
            # Update quantity if already in cart
            new_quantity = cart_item.quantity + quantity
            
            # Check stock again with new total quantity
            if new_quantity > product.stock:
                if request.is_json:
                    return jsonify({"error": f"Not enough stock. Only {product.stock} available."}), 400
                else:
                    flash(f"Not enough stock. Only {product.stock} available.", "warning")
                    return redirect(url_for('product.get_product', product_id=product_id))
            
            cart_item.quantity = new_quantity
        else:
            # Add new item to cart
            cart_item = CartItem(
                cart_id=cart.id,
                product_id=product_id,
                quantity=quantity,
                price=product.price
            )
            db.session.add(cart_item)
        
        # Update cart timestamp
        cart.updated_at = db.func.now()
        
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                "message": f"Added {quantity} {product.name} to cart",
                "cart_item": cart_item.to_dict(),
                "cart": cart.to_dict()
            })
        else:
            flash(f"Added {quantity} {product.name} to cart", "success")
            return redirect(url_for('cart.view_cart'))
    
    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Error adding to cart: {str(e)}")
        
        if request.is_json:
            return jsonify({"error": "Failed to add item to cart"}), 500
        else:
            flash("Failed to add item to cart", "danger")
            return redirect(url_for('product.get_product', product_id=product_id))

@bp.route('/items/<int:item_id>', methods=['PUT', 'POST'])
@login_required
def update_cart_item(item_id):
    """Update quantity of an item in the cart"""
    user_id = session.get('user_id')
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    quantity = int(data.get('quantity', 1))
    
    # Validate input
    if quantity < 1:
        if request.is_json:
            return jsonify({"error": "Quantity must be at least 1"}), 400
        else:
            flash("Quantity must be at least 1", "danger")
            return redirect(url_for('cart.view_cart'))
    
    try:
        # Get cart item
        cart_item = CartItem.query.get_or_404(item_id)
        
        # Check if item belongs to user's cart
        cart = Cart.query.get(cart_item.cart_id)
        if not cart or cart.user_id != user_id:
            if request.is_json:
                return jsonify({"error": "Cart item not found"}), 404
            else:
                flash("Cart item not found", "danger")
                return redirect(url_for('cart.view_cart'))
        
        # Get product to check stock
        product = Product.query.get(cart_item.product_id)
        
        # Check stock
        if quantity > product.stock:
            if request.is_json:
                return jsonify({"error": f"Not enough stock. Only {product.stock} available."}), 400
            else:
                flash(f"Not enough stock. Only {product.stock} available.", "warning")
                return redirect(url_for('cart.view_cart'))
        
        # Update quantity
        cart_item.quantity = quantity
        
        # Update cart timestamp
        cart.updated_at = db.func.now()
        
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                "message": "Cart item updated",
                "cart_item": cart_item.to_dict(),
                "cart": cart.to_dict()
            })
        else:
            flash("Cart item updated", "success")
            return redirect(url_for('cart.view_cart'))
    
    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating cart item: {str(e)}")
        
        if request.is_json:
            return jsonify({"error": "Failed to update cart item"}), 500
        else:
            flash("Failed to update cart item", "danger")
            return redirect(url_for('cart.view_cart'))

@bp.route('/items/<int:item_id>', methods=['DELETE'])
@login_required
def remove_from_cart(item_id):
    """Remove an item from the cart"""
    user_id = session.get('user_id')
    
    try:
        # Get cart item
        cart_item = CartItem.query.get_or_404(item_id)
        
        # Check if item belongs to user's cart
        cart = Cart.query.get(cart_item.cart_id)
        if not cart or cart.user_id != user_id:
            if request.is_json:
                return jsonify({"error": "Cart item not found"}), 404
            else:
                flash("Cart item not found", "danger")
                return redirect(url_for('cart.view_cart'))
        
        # Get product name for success message
        product_name = Product.query.get(cart_item.product_id).name
        
        # Remove item
        db.session.delete(cart_item)
        
        # Update cart timestamp
        cart.updated_at = db.func.now()
        
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                "message": f"Removed {product_name} from cart",
                "cart": cart.to_dict()
            })
        else:
            flash(f"Removed {product_name} from cart", "success")
            return redirect(url_for('cart.view_cart'))
    
    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Error removing from cart: {str(e)}")
        
        if request.is_json:
            return jsonify({"error": "Failed to remove item from cart"}), 500
        else:
            flash("Failed to remove item from cart", "danger")
            return redirect(url_for('cart.view_cart'))

@bp.route('/', methods=['DELETE'])
@login_required
def clear_cart():
    """Remove all items from the cart"""
    user_id = session.get('user_id')
    
    try:
        # Get user's active cart
        cart = Cart.query.filter_by(user_id=user_id, status='active').first()
        
        if not cart:
            if request.is_json:
                return jsonify({"message": "Cart already empty"})
            else:
                flash("Cart already empty", "info")
                return redirect(url_for('cart.view_cart'))
        
        # Remove all items
        CartItem.query.filter_by(cart_id=cart.id).delete()
        
        # Update cart timestamp
        cart.updated_at = db.func.now()
        
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                "message": "Cart cleared",
                "cart": cart.to_dict()
            })
        else:
            flash("Cart cleared", "success")
            return redirect(url_for('cart.view_cart'))
    
    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Error clearing cart: {str(e)}")
        
        if request.is_json:
            return jsonify({"error": "Failed to clear cart"}), 500
        else:
            flash("Failed to clear cart", "danger")
            return redirect(url_for('cart.view_cart'))
