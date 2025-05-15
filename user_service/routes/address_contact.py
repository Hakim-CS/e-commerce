from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_jwt_extended import jwt_required, get_jwt_identity

from app import db
from models import User, Address, Contact

bp = Blueprint('address_contact', __name__, url_prefix='/address')

# Address endpoints
@bp.route('/', methods=['GET'])
@jwt_required()
def get_addresses():
    """Get all addresses for the current user"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    addresses = Address.query.filter_by(user_id=current_user_id).all()
    
    if request.is_json:
        return jsonify({
            "addresses": [{
                "id": address.id,
                "user_id": address.user_id,
                "address_type": address.address_type,
                "street": address.street,
                "city": address.city,
                "state": address.state,
                "postal_code": address.postal_code,
                "country": address.country,
                "is_default": address.is_default,
                "created_at": address.created_at.isoformat(),
                "updated_at": address.updated_at.isoformat()
            } for address in addresses]
        })
    else:
        return render_template('user/address.html', addresses=addresses, user=user)

@bp.route('/', methods=['POST'])
@jwt_required()
def create_address():
    """Create a new address"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    # Required fields validation
    required_fields = ['address_type', 'street', 'city', 'postal_code', 'country']
    for field in required_fields:
        if not data.get(field):
            if request.is_json:
                return jsonify({"error": f"{field} is required"}), 400
            else:
                flash(f"{field} is required", 'danger')
                return redirect(url_for('address_contact.get_addresses'))
    
    # Check if it's set as default
    is_default = data.get('is_default') in ['true', 'True', True, 1, '1']
    
    # If this address is set as default, unset any other default addresses
    if is_default:
        default_addresses = Address.query.filter_by(user_id=current_user_id, is_default=True).all()
        for addr in default_addresses:
            addr.is_default = False
    
    # Create new address
    new_address = Address(
        user_id=current_user_id,
        address_type=data.get('address_type'),
        street=data.get('street'),
        city=data.get('city'),
        state=data.get('state'),
        postal_code=data.get('postal_code'),
        country=data.get('country'),
        is_default=is_default
    )
    
    db.session.add(new_address)
    db.session.commit()
    
    if request.is_json:
        return jsonify({
            "id": new_address.id,
            "user_id": new_address.user_id,
            "address_type": new_address.address_type,
            "street": new_address.street,
            "city": new_address.city,
            "state": new_address.state,
            "postal_code": new_address.postal_code,
            "country": new_address.country,
            "is_default": new_address.is_default,
            "message": "Address created successfully"
        }), 201
    else:
        flash('Address created successfully', 'success')
        return redirect(url_for('address_contact.get_addresses'))

@bp.route('/<int:address_id>', methods=['PUT', 'POST'])
@jwt_required()
def update_address(address_id):
    """Update an address"""
    current_user_id = get_jwt_identity()
    
    address = Address.query.get(address_id)
    if not address:
        return jsonify({"error": "Address not found"}), 404
    
    # Security check: ensure the address belongs to the current user
    if address.user_id != current_user_id:
        return jsonify({"error": "Unauthorized"}), 403
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    # Update address fields
    if 'address_type' in data:
        address.address_type = data.get('address_type')
    if 'street' in data:
        address.street = data.get('street')
    if 'city' in data:
        address.city = data.get('city')
    if 'state' in data:
        address.state = data.get('state')
    if 'postal_code' in data:
        address.postal_code = data.get('postal_code')
    if 'country' in data:
        address.country = data.get('country')
    
    # Check if it's set as default
    if 'is_default' in data:
        is_default = data.get('is_default') in ['true', 'True', True, 1, '1']
        
        # If this address is set as default, unset any other default addresses
        if is_default and not address.is_default:
            default_addresses = Address.query.filter_by(user_id=current_user_id, is_default=True).all()
            for addr in default_addresses:
                addr.is_default = False
        
        address.is_default = is_default
    
    db.session.commit()
    
    if request.is_json:
        return jsonify({
            "id": address.id,
            "user_id": address.user_id,
            "address_type": address.address_type,
            "street": address.street,
            "city": address.city,
            "state": address.state,
            "postal_code": address.postal_code,
            "country": address.country,
            "is_default": address.is_default,
            "message": "Address updated successfully"
        })
    else:
        flash('Address updated successfully', 'success')
        return redirect(url_for('address_contact.get_addresses'))

@bp.route('/<int:address_id>', methods=['DELETE'])
@jwt_required()
def delete_address(address_id):
    """Delete an address"""
    current_user_id = get_jwt_identity()
    
    address = Address.query.get(address_id)
    if not address:
        return jsonify({"error": "Address not found"}), 404
    
    # Security check: ensure the address belongs to the current user
    if address.user_id != current_user_id:
        return jsonify({"error": "Unauthorized"}), 403
    
    db.session.delete(address)
    db.session.commit()
    
    if request.is_json:
        return jsonify({
            "id": address_id,
            "message": "Address deleted successfully"
        })
    else:
        flash('Address deleted successfully', 'success')
        return redirect(url_for('address_contact.get_addresses'))

# Contact endpoints
@bp.route('/contact', methods=['GET'])
@jwt_required()
def get_contacts():
    """Get all contacts for the current user"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    contacts = Contact.query.filter_by(user_id=current_user_id).all()
    
    if request.is_json:
        return jsonify({
            "contacts": [{
                "id": contact.id,
                "user_id": contact.user_id,
                "contact_type": contact.contact_type,
                "phone_number": contact.phone_number,
                "email": contact.email,
                "is_default": contact.is_default,
                "created_at": contact.created_at.isoformat(),
                "updated_at": contact.updated_at.isoformat()
            } for contact in contacts]
        })
    else:
        return render_template('user/contact.html', contacts=contacts, user=user)

@bp.route('/contact', methods=['POST'])
@jwt_required()
def create_contact():
    """Create a new contact"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    # Required fields validation
    if not data.get('contact_type'):
        if request.is_json:
            return jsonify({"error": "Contact type is required"}), 400
        else:
            flash('Contact type is required', 'danger')
            return redirect(url_for('address_contact.get_contacts'))
    
    # At least one of phone or email must be provided
    if not data.get('phone_number') and not data.get('email'):
        if request.is_json:
            return jsonify({"error": "Either phone number or email is required"}), 400
        else:
            flash('Either phone number or email is required', 'danger')
            return redirect(url_for('address_contact.get_contacts'))
    
    # Check if it's set as default
    is_default = data.get('is_default') in ['true', 'True', True, 1, '1']
    
    # If this contact is set as default, unset any other default contacts
    if is_default:
        default_contacts = Contact.query.filter_by(user_id=current_user_id, is_default=True).all()
        for contact in default_contacts:
            contact.is_default = False
    
    # Create new contact
    new_contact = Contact(
        user_id=current_user_id,
        contact_type=data.get('contact_type'),
        phone_number=data.get('phone_number'),
        email=data.get('email'),
        is_default=is_default
    )
    
    db.session.add(new_contact)
    db.session.commit()
    
    if request.is_json:
        return jsonify({
            "id": new_contact.id,
            "user_id": new_contact.user_id,
            "contact_type": new_contact.contact_type,
            "phone_number": new_contact.phone_number,
            "email": new_contact.email,
            "is_default": new_contact.is_default,
            "message": "Contact created successfully"
        }), 201
    else:
        flash('Contact created successfully', 'success')
        return redirect(url_for('address_contact.get_contacts'))

@bp.route('/contact/<int:contact_id>', methods=['PUT', 'POST'])
@jwt_required()
def update_contact(contact_id):
    """Update a contact"""
    current_user_id = get_jwt_identity()
    
    contact = Contact.query.get(contact_id)
    if not contact:
        return jsonify({"error": "Contact not found"}), 404
    
    # Security check: ensure the contact belongs to the current user
    if contact.user_id != current_user_id:
        return jsonify({"error": "Unauthorized"}), 403
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    # Update contact fields
    if 'contact_type' in data:
        contact.contact_type = data.get('contact_type')
    if 'phone_number' in data:
        contact.phone_number = data.get('phone_number')
    if 'email' in data:
        contact.email = data.get('email')
    
    # Check if it's set as default
    if 'is_default' in data:
        is_default = data.get('is_default') in ['true', 'True', True, 1, '1']
        
        # If this contact is set as default, unset any other default contacts
        if is_default and not contact.is_default:
            default_contacts = Contact.query.filter_by(user_id=current_user_id, is_default=True).all()
            for cont in default_contacts:
                cont.is_default = False
        
        contact.is_default = is_default
    
    db.session.commit()
    
    if request.is_json:
        return jsonify({
            "id": contact.id,
            "user_id": contact.user_id,
            "contact_type": contact.contact_type,
            "phone_number": contact.phone_number,
            "email": contact.email,
            "is_default": contact.is_default,
            "message": "Contact updated successfully"
        })
    else:
        flash('Contact updated successfully', 'success')
        return redirect(url_for('address_contact.get_contacts'))

@bp.route('/contact/<int:contact_id>', methods=['DELETE'])
@jwt_required()
def delete_contact(contact_id):
    """Delete a contact"""
    current_user_id = get_jwt_identity()
    
    contact = Contact.query.get(contact_id)
    if not contact:
        return jsonify({"error": "Contact not found"}), 404
    
    # Security check: ensure the contact belongs to the current user
    if contact.user_id != current_user_id:
        return jsonify({"error": "Unauthorized"}), 403
    
    db.session.delete(contact)
    db.session.commit()
    
    if request.is_json:
        return jsonify({
            "id": contact_id,
            "message": "Contact deleted successfully"
        })
    else:
        flash('Contact deleted successfully', 'success')
        return redirect(url_for('address_contact.get_contacts'))
