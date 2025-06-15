"""
============================
🗓️ GOALS FOR 15-JUNE-2025
============================
✅ 1. Fix email verification bug (token decoding issue)
✅ 2. Complete full registration → verification → login flow
⬜ 3. Test forgot/reset password functionality
⬜ 4. Test admin routes (user listing, role change, delete)
⬜ 5. Ensure all error codes and messages are consistent
============================
"""

import os
from flask import Blueprint, request, jsonify, abort, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db, mail
from models.user import User
from utils.auth_util import token_required, role_required, generate_reset_token, verify_reset_token
from utils.blacklist_util import add_to_blacklist, is_blacklisted
from utils.jwt_util import generate_token, decode_token, generate_refresh_token, generate_email_verification_token
from flask_mail import Message

user_bp = Blueprint('user_bp', __name__)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# ✅ Fixed: Email Verification Route
@user_bp.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    payload = decode_token(token)
    user_id = payload.get('user_id') if payload else None

    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.is_verified:
        return jsonify({'message': 'Email already verified'}), 200

    user.is_verified = True
    db.session.commit()
    return jsonify({'message': 'Email verified successfully!'}), 200


# ===================
# ✅ USER ROUTES
# ===================

@user_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data.get('name') or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Name, email, and password are required'}), 400

    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'error': 'User already exists'}), 409

    new_user = User(
        name=data['name'],
        email=data['email'],
        password=generate_password_hash(data['password']),
        role=data.get('role', 'user'),
        is_verified=False
    )
    db.session.add(new_user)
    db.session.commit()

    token = generate_email_verification_token(new_user.id)
    verify_link = url_for('user_bp.verify_email', token=token, _external=True)
    msg = Message('Verify your email', recipients=[new_user.email])
    msg.body = f'Hi {new_user.name}, please click the link to verify your email: {verify_link}'
    mail.send(msg)

    return jsonify({'message': 'User registered successfully. Please check your email to verify your account.'}), 201


@user_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()

    if not user or not check_password_hash(user.password, data.get('password')):
        return jsonify({'error': 'Incorrect email or password'}), 401
    if not user.is_verified:
        return jsonify({'error': 'Email not verified. Please check your inbox.'}), 403

    access_token = generate_token(user.id, user.role)
    refresh_token = generate_refresh_token(user.id)
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200


@user_bp.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user_id):
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    return jsonify({
        'message': f'Welcome {user.name}!',
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role
            # 'avatar': user.avatar
        }
    })


@user_bp.route('/profile', methods=['PUT'])
@token_required
def update_profile(current_user_id):
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON data'}), 400

    user.name = data.get('name', user.name)
    user.email = data.get('email', user.email)
    db.session.commit()

    return jsonify({
        'message': 'Profile updated successfully',
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role
        }
    }), 200


@user_bp.route('/change-password', methods=['POST'])
@token_required
def change_password(current_user_id):
    data = request.get_json()
    if not data or not data.get('old_password') or not data.get('new_password'):
        return jsonify({'error': "Old and new passwords are required"}), 400

    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not check_password_hash(user.password, data['old_password']):
        return jsonify({'error': 'Old password is incorrect'}), 401

    user.password = generate_password_hash(data['new_password'])
    db.session.commit()
    return jsonify({'message': 'Password changed successfully'}), 200


@user_bp.route('/logout', methods=['POST'])
@token_required
def logout(current_user_id):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Token missing'}), 400

    token = auth_header.split(" ")[1]
    add_to_blacklist(token)
    return jsonify({"message": "Logged out successfully."}), 200


@user_bp.route('/refresh-token', methods=['POST'])
def refresh():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Refresh token missing'}), 401

    refresh_token = auth_header.split(' ')[1]
    if is_blacklisted(refresh_token):
        return jsonify({'error': 'Refresh token has been blacklisted'}), 401

    payload = decode_token(refresh_token)
    if not payload:
        return jsonify({'error': 'Invalid or expired refresh token'}), 401

    user_id = payload.get('user_id')
    new_access_token = generate_token(user_id)
    return jsonify({'access_token': new_access_token}), 200


@user_bp.route('/admin/data', methods=['GET'])
@token_required
@role_required(['admin'])
def admin_data(current_user_id):
    return jsonify({'data': 'Sensitive admin-only data'})


@user_bp.route('/users', methods=['GET'])
@token_required
@role_required(['admin'])
def get_all_users(current_user_id):
    users = User.query.all()
    user_list = [{
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'role': user.role
    } for user in users]
    return jsonify(user_list), 200


@user_bp.route('/user/<int:user_id>', methods=['GET'])
@token_required
def get_user_by_id(current_user_id, user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if current_user_id != user.id:
        requester = User.query.get(current_user_id)
        if requester.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403

    return jsonify({
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'role': user.role
    }), 200


@user_bp.route('/user/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user_id, user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if current_user_id != user.id:
        requester = User.query.get(current_user_id)
        if requester.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403

    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'}), 200


@user_bp.route('/user/<int:user_id>/role', methods=['PATCH'])
@token_required
@role_required(['admin'])
def change_user_role(current_user_id, user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    new_role = data.get('role')
    if not new_role:
        return jsonify({'error': 'Role is required'}), 400

    user.role = new_role
    db.session.commit()
    return jsonify({'message': 'User role updated successfully'}), 200


@user_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    token = generate_reset_token(user.id)
    reset_link = url_for('user_bp.reset_password', token=token, _external=True)

    msg = Message('Password Reset Request', recipients=[user.email])
    msg.body = f"Click the link to reset your password: {reset_link}"
    mail.send(msg)

    return jsonify({'message': 'Password reset link sent to your email'}), 200


@user_bp.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    user_id = verify_reset_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    new_password = data.get('new_password')
    if not new_password:
        return jsonify({'error': 'New password required'}), 400

    user.password = generate_password_hash(new_password)
    db.session.commit()
    return jsonify({'message': 'Password reset successful'}), 200


@user_bp.route('/send-verification-email', methods=['POST'])
@token_required
def send_verification_email(current_user_id):
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.is_verified:
        return jsonify({'message': 'Email already verified'}), 200

    token = generate_email_verification_token(user.id)
    verify_link = url_for('user_bp.verify_email', token=token, _external=True)

    msg = Message('Verify Your Email', recipients=[user.email])
    msg.body = f"Click the link to verify your email: {verify_link}"
    mail.send(msg)

    return jsonify({'message': 'Verification email sent'}), 200


@user_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.is_verified:
        return jsonify({'message': 'Email is already verified'}), 200

    token = generate_email_verification_token(user.id)
    verify_link = url_for('user_bp.verify_email', token=token, _external=True)
    msg = Message('Verify your email', recipients=[user.email])
    msg.body = f'Hi {user.name}, please click the link to verify your email: {verify_link}'
    mail.send(msg)

    return jsonify({'message': 'Verification email resent. Please check your inbox.'}), 200
