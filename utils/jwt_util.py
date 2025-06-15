import jwt
from datetime import datetime,timedelta

SECRET_KEY = "myverysecretkey12345"  # Use env var in real apps
EMAIL_SECRET_KEY = "myverysecretkey12345"

def generate_token(user_id, role='user', expires_in=15):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(minutes=expires_in)
    }
    print(f"[TOKEN PAYLOAD] {payload}")
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def generate_refresh_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=7)  # 7 days validity
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def decode_token(token):
    try:
        print(f"[DECODE] Decoding token: {token}")
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None  # Token is expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

def generate_email_verification_token(user_id, expires_in=3600):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(seconds=expires_in)
    }
    return jwt.encode(payload, EMAIL_SECRET_KEY, algorithm='HS256')

