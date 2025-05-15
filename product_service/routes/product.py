import json
import requests
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session, current_app
from sqlalchemy import or_

from app import db, USER_SERVICE_URL
from models import Product
from utils.auth import admin_required, permission_required

bp = Blueprint('product', __name__)

@bp.route('/', methods=['GET'])
@bp.route('/products', methods=['GET'])
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
        query = query.filter(
            or_(
                Product.name.ilike(f'%{search}%'),
                Product.description.ilike(f'%{search}%'),
                Product.sku.ilike(f'%{search}%'),
                Product.barcode.ilike(f'%{search}%')
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
    
    if request.headers.get('Accept') == 'application/json' or request.is_json:
        return jsonify({
            'products': [product.to_dict() for product in products.items],
            'pagination': {
                'page': products.page,
                'per_page': products.per_page,
                'total': products.total,
                'pages': products.pages
            }
        })
    else:
        return render_template(
            'products/list.html', 
            products=products,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order
        )

@bp.route('/products/<int:product_id>', methods=['GET'])
@bp.route('/product/details/<int:product_id>', methods=['GET'])
def get_product(product_id):
    """Get details of a specific product"""
    product = Product.query.get_or_404(product_id)
    
    # Don't show deleted products unless admin
    if product.is_deleted and not session.get('is_admin'):
        return jsonify({"error": "Product not found"}), 404
    
    if request.headers.get('Accept') == 'application/json' or request.is_json:
        return jsonify(product.to_dict())
    else:
        return render_template('products/detail.html', product=product)

@bp.route('/product', methods=['POST'])
@permission_required('product.create')
def create_product():
    """Create a new product (admin only)"""
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    # Validate required fields
    required_fields = ['name', 'sku', 'barcode', 'price']
    for field in required_fields:
        if not data.get(field):
            if request.is_json:
                return jsonify({"error": f"Field '{field}' is required"}), 400
            else:
                flash(f"Field '{field}' is required", "danger")
                return redirect(url_for('product.admin_products'))
    
    # Check for duplicate SKU or barcode
    existing_product = Product.query.filter(
        (Product.sku == data.get('sku')) | 
        (Product.barcode == data.get('barcode'))
    ).first()
    
    if existing_product:
        if request.is_json:
            return jsonify({"error": "A product with this SKU or barcode already exists"}), 400
        else:
            flash("A product with this SKU or barcode already exists", "danger")
            return redirect(url_for('product.admin_products'))
    
    try:
        # Create new product
        new_product = Product(
            name=data.get('name'),
            sku=data.get('sku'),
            barcode=data.get('barcode'),
            description=data.get('description', ''),
            price=float(data.get('price')),
            stock=int(data.get('stock', 0))
        )
        
        db.session.add(new_product)
        db.session.commit()
        
        if request.is_json:
            return jsonify(new_product.to_dict()), 201
        else:
            flash(f"Product '{new_product.name}' created successfully", "success")
            return redirect(url_for('product.admin_products'))
    
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating product: {str(e)}")
        
        if request.is_json:
            return jsonify({"error": str(e)}), 500
        else:
            flash(f"Error creating product: {str(e)}", "danger")
            return redirect(url_for('product.admin_products'))

@bp.route('/product/<int:product_id>', methods=['PUT', 'POST'])
@permission_required('product.update')
def update_product(product_id):
    """Update a product (admin only)"""
    product = Product.query.get_or_404(product_id)
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    try:
        # Update product fields if provided
        if 'name' in data:
            product.name = data.get('name')
        if 'sku' in data:
            # Check for duplicate SKU
            existing = Product.query.filter(Product.sku == data.get('sku'), Product.id != product_id).first()
            if existing:
                if request.is_json:
                    return jsonify({"error": "A product with this SKU already exists"}), 400
                else:
                    flash("A product with this SKU already exists", "danger")
                    return redirect(url_for('product.edit_product', product_id=product_id))
            product.sku = data.get('sku')
        if 'barcode' in data:
            # Check for duplicate barcode
            existing = Product.query.filter(Product.barcode == data.get('barcode'), Product.id != product_id).first()
            if existing:
                if request.is_json:
                    return jsonify({"error": "A product with this barcode already exists"}), 400
                else:
                    flash("A product with this barcode already exists", "danger")
                    return redirect(url_for('product.edit_product', product_id=product_id))
            product.barcode = data.get('barcode')
        if 'description' in data:
            product.description = data.get('description')
        if 'price' in data:
            product.price = float(data.get('price'))
        if 'stock' in data:
            product.stock = int(data.get('stock'))
        if 'is_deleted' in data:
            product.is_deleted = data.get('is_deleted') in [True, 'true', 'True', 1, '1']
        
        db.session.commit()
        
        if request.is_json:
            return jsonify(product.to_dict())
        else:
            flash(f"Product '{product.name}' updated successfully", "success")
            return redirect(url_for('product.admin_products'))
    
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating product: {str(e)}")
        
        if request.is_json:
            return jsonify({"error": str(e)}), 500
        else:
            flash(f"Error updating product: {str(e)}", "danger")
            return redirect(url_for('product.edit_product', product_id=product_id))

@bp.route('/product/<int:product_id>', methods=['DELETE'])
@permission_required('product.delete')
def delete_product(product_id):
    """Soft delete a product (admin only)"""
    product = Product.query.get_or_404(product_id)
    
    try:
        # Soft delete by setting is_deleted flag
        product.is_deleted = True
        db.session.commit()
        
        if request.is_json:
            return jsonify({"message": f"Product '{product.name}' deleted successfully"})
        else:
            flash(f"Product '{product.name}' deleted successfully", "success")
            return redirect(url_for('product.admin_products'))
    
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting product: {str(e)}")
        
        if request.is_json:
            return jsonify({"error": str(e)}), 500
        else:
            flash(f"Error deleting product: {str(e)}", "danger")
            return redirect(url_for('product.admin_products'))

@bp.route('/admin/products', methods=['GET'])
@admin_required
def admin_products():
    """Admin view for managing products"""
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
        query = query.filter(
            or_(
                Product.name.ilike(f'%{search}%'),
                Product.sku.ilike(f'%{search}%'),
                Product.barcode.ilike(f'%{search}%')
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

@bp.route('/admin/products/new', methods=['GET'])
@admin_required
def new_product():
    """Admin form for creating a new product"""
    return render_template('admin/product_edit.html', product=None, is_new=True)

@bp.route('/admin/products/<int:product_id>/edit', methods=['GET'])
@admin_required
def edit_product(product_id):
    """Admin form for editing a product"""
    product = Product.query.get_or_404(product_id)
    return render_template('admin/product_edit.html', product=product, is_new=False)

@bp.route('/admin/products/<int:product_id>/delete', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    """Admin route to delete a product"""
    return delete_product(product_id)

@bp.route('/login')
def login():
    """Redirect to user service login"""
    return redirect(f"{USER_SERVICE_URL}/auth/login")

@bp.route('/logout')
def logout():
    """Logout and redirect to user service logout"""
    session.clear()
    return redirect(f"{USER_SERVICE_URL}/auth/logout")
