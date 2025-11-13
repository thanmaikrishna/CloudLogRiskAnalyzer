import json
import os
from passlib.hash import pbkdf2_sha256
from functools import wraps
from flask import request, jsonify
import jwt
from config import SECRET_KEY

USERS_FILE = 'users.json'

def load_users():
    if not os.path.exists(USERS_FILE):
        print("users.json does not exist, creating empty file.")
        return {}
    try:
        with open(USERS_FILE, 'r') as f:
            data = json.load(f)
            if not isinstance(data, dict):
                print("Invalid data format in users.json")
                return {}
            return data
    except Exception as e:
        print("Error loading users.json:", e)
        return {}


def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)


def register_user(email, password, update=False):
    users = load_users()
    if not update and email in users:
        return False, 'User already exists'
    hashed = pbkdf2_sha256.hash(password)
    users[email] = hashed
    save_users(users)
    return True, 'User registered' if not update else 'Password updated'


def authenticate_user(email, password):
    users = load_users()
    hashed = users.get(email)
    if not hashed:
        return False
    try:
        return pbkdf2_sha256.verify(password, hashed)
    except Exception:
        return False
    
def forgot_password(email, new_password):
    users = load_users()
    if email not in users:
        return False, "User does not exist"
    hashed = pbkdf2_sha256.hash(new_password)
    users[email] = hashed
    save_users(users)
    return True, "Password reset successful"

import smtplib
from email.mime.text import MIMEText

def send_reset_email(to_email, reset_link):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "your_email@gmail.com"
    sender_password = "your_app_password"  # Use App Password if 2FA enabled

    subject = "Password Reset Link"
    body = f"Click this link to reset your password:\n\n{reset_link}\n\nLink expires in 1 hour."

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()
        print(f"Password reset email sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Handle CORS preflight
        if request.method == 'OPTIONS':
            return f(*args, **kwargs)

        token = None
        auth_header = request.headers.get('Authorization')

        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'message': 'Authorization token is missing'}), 401

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = payload['email']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Session expired. Please login again.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token. Please login again.'}), 401
        except Exception as e:
            return jsonify({'message': 'Authentication failed', 'error': str(e)}), 401

        return f(current_user, *args, **kwargs)

    return decorated
