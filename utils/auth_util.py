# Example: auth_util.py or utils.py
import jwt
from functools import wraps
from flask import request, jsonify
from utils.blacklist_util import is_blacklisted
from utils.jwt_util import decode_token
from itsdangerous import URLSafeTimedSerializer

SECRET_KEY = "myverysecretkey12345"  # Should match app secret
RESET_SECRET = "reset-secret-key"  # Ideally store in env

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        print("Inside token_required decorator")
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            print(f"Authorization header received: {auth_header}")
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
                print(f"Token extracted: {token}")

        if not token:
            print("No token found in request")
            return jsonify({'error': 'Token is missing!'}), 401

        if is_blacklisted(token):
            print("Token is blacklisted")
            return jsonify({'error': 'Token has been blacklisted!'}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            print(f"Token decoded successfully: {data}")
            current_user = data['user_id']  # use 'user_id' as per your token payload
        except jwt.ExpiredSignatureError:
            print("Token expired error caught")
            return jsonify({'error': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            print("Invalid token error caught")
            return jsonify({'error': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

def role_required(required_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(current_user_id, *args, **kwargs):
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[1]
            payload = decode_token(token)

            print(f"[RBAC] Token payload: {payload}")

            if not payload:
                return jsonify({'error': 'Invalid token!'}), 401

            user_role = payload.get('role')
            print(f"[RBAC] User role: {user_role}, Required: {required_roles}")

            if user_role not in required_roles:
                return jsonify({'error': 'Unauthorized - insufficient role'}), 403

            return f(current_user_id, *args, **kwargs)
        return wrapper
    return decorator

def generate_reset_token(user_id, expires_sec=900):  # 15 minutes
    s = URLSafeTimedSerializer(RESET_SECRET)
    return s.dumps({'user_id': user_id})

def verify_reset_token(token, max_age=900):  # 15 minutes validity
    s = URLSafeTimedSerializer(RESET_SECRET)
    try:
        data = s.loads(token, max_age=max_age)
        return data['user_id']
    except Exception:
        return None






