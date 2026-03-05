import sqlite3
import hashlib
import jwt
import datetime
import secrets
from functools import wraps
from flask import request, jsonify
import os

DATABASE_PATH = 'stego_app.db'
SECRET_KEY = 'your-secret-key-change-in-production-' + os.urandom(16).hex()


def get_db_connection():
    """Create database connection"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn


def init_database():
    """Initialize database with all tables and automatic migration"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        users_table_exists = cursor.fetchone() is not None
        
        if users_table_exists:
            # Table exists, check if we need to add is_verified column
            cursor.execute("PRAGMA table_info(users)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'is_verified' not in columns:
                print("🔄 Migrating existing database: adding is_verified column...")
                cursor.execute('ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 1')
                print("   ✅ is_verified column added (existing users auto-verified)")
        else:
            # Create new users table with is_verified
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_verified INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            print("✅ Created users table")
        
        # Email verification tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_verification_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        print("✅ Email verification tokens table ready")
        
        # Password reset tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        print("✅ Password reset tokens table ready")
        
        # Stego history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stego_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                filename TEXT,
                message_preview TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        print("✅ Stego history table ready")
        
        conn.commit()
        print("✅ Database initialized with email verification and password reset!")
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Database initialization error: {e}")
        raise
    finally:
        conn.close()


def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash"""
    return hash_password(password) == password_hash


def generate_token() -> str:
    """Generate secure random token"""
    return secrets.token_urlsafe(32)


def create_jwt_token(user_id: int, username: str) -> str:
    """Create JWT token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)  # 7 days expiry
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    # PyJWT may return a bytes object in some versions; ensure we return a str
    if isinstance(token, bytes):
        return token.decode('utf-8')
    return token


def decode_jwt_token(token: str):
    """Decode JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    """Decorator to protect routes with JWT authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid authorization header format'}), 401
        
        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401
        
        # Verify token
        payload = decode_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Check if user is verified
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT is_verified FROM users WHERE id = ?', (payload['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user or not user['is_verified']:
            return jsonify({'error': 'Email not verified. Please verify your email first.'}), 403
        
        # Add user info to kwargs
        return f(current_user=payload, *args, **kwargs)
    
    return decorated


def register_user(username: str, email: str, password: str):
    """Register new user and create verification token"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Validate
        if len(password) < 6:
            return {'error': 'Password must be at least 6 characters'}, 400
        
        if not username or not email:
            return {'error': 'Username and email are required'}, 400
        
        # Hash password
        password_hash = hash_password(password)
        
        # Insert user (not verified initially)
        cursor.execute(
            'INSERT INTO users (username, email, password_hash, is_verified) VALUES (?, ?, ?, 0)',
            (username, email, password_hash)
        )
        user_id = cursor.lastrowid
        
        # Create verification token (expires in 24 hours)
        verification_token = generate_token()
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        
        cursor.execute(
            'INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
            (user_id, verification_token, expires_at)
        )
        
        conn.commit()
        
        return {
            'success': True,
            'message': 'Registration successful! Please check your email to verify your account.',
            'user': {
                'id': user_id,
                'username': username,
                'email': email,
                'is_verified': False
            },
            'verification_token': verification_token  # Send this via email
        }, 201
        
    except sqlite3.IntegrityError:
        return {'error': 'Username or email already exists'}, 409
    except Exception as e:
        conn.rollback()
        return {'error': f'Registration failed: {str(e)}'}, 500
    finally:
        conn.close()


def verify_email(token: str):
    """Verify user email with token"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Find token
        cursor.execute('''
            SELECT * FROM email_verification_tokens 
            WHERE token = ? AND used = 0 AND expires_at > ?
        ''', (token, datetime.datetime.utcnow()))
        
        token_record = cursor.fetchone()
        
        if not token_record:
            return {'error': 'Invalid or expired verification token'}, 400
        
        # Mark token as used
        cursor.execute(
            'UPDATE email_verification_tokens SET used = 1 WHERE id = ?',
            (token_record['id'],)
        )
        
        # Verify user
        cursor.execute(
            'UPDATE users SET is_verified = 1 WHERE id = ?',
            (token_record['user_id'],)
        )
        
        # Get user info
        cursor.execute('SELECT id, username, email FROM users WHERE id = ?', (token_record['user_id'],))
        user = cursor.fetchone()
        
        conn.commit()
        
        # Create JWT token
        jwt_token = create_jwt_token(user['id'], user['username'])
        
        return {
            'success': True,
            'message': 'Email verified successfully! You can now log in.',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'is_verified': True
            },
            'token': jwt_token
        }, 200
        
    except Exception as e:
        conn.rollback()
        return {'error': f'Verification failed: {str(e)}'}, 500
    finally:
        conn.close()


def resend_verification_email(email: str):
    """Resend verification email"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Find user
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if not user:
            return {'error': 'Email not found'}, 404
        
        if user['is_verified']:
            return {'error': 'Email already verified'}, 400
        
        # Create new verification token
        verification_token = generate_token()
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        
        cursor.execute(
            'INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
            (user['id'], verification_token, expires_at)
        )
        
        conn.commit()
        
        return {
            'success': True,
            'message': 'Verification email sent! Please check your inbox.',
            'verification_token': verification_token,
            'username': user['username']
        }, 200
        
    except Exception as e:
        conn.rollback()
        return {'error': f'Failed to resend verification: {str(e)}'}, 500
    finally:
        conn.close()


def request_password_reset(email: str):
    """Create password reset token"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Find user
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if not user:
            # Don't reveal if email exists or not (security)
            return {
                'success': True,
                'message': 'If that email exists, a password reset link has been sent.'
            }, 200
        
        # Create reset token (expires in 1 hour)
        reset_token = generate_token()
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        
        cursor.execute(
            'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
            (user['id'], reset_token, expires_at)
        )
        
        conn.commit()
        
        return {
            'success': True,
            'message': 'Password reset link has been sent to your email.',
            'reset_token': reset_token,  # Send this via email
            'username': user['username']
        }, 200
        
    except Exception as e:
        conn.rollback()
        return {'error': f'Failed to request password reset: {str(e)}'}, 500
    finally:
        conn.close()


def verify_reset_token(token: str):
    """Verify if reset token is valid"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT * FROM password_reset_tokens 
            WHERE token = ? AND used = 0 AND expires_at > ?
        ''', (token, datetime.datetime.utcnow()))
        
        token_record = cursor.fetchone()
        
        if not token_record:
            return {'valid': False, 'error': 'Invalid or expired reset token'}, 400
        
        return {'valid': True}, 200
        
    finally:
        conn.close()


def reset_password(token: str, new_password: str):
    """Reset password with token"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Validate password
        if len(new_password) < 6:
            return {'error': 'Password must be at least 6 characters'}, 400
        
        # Find token
        cursor.execute('''
            SELECT * FROM password_reset_tokens 
            WHERE token = ? AND used = 0 AND expires_at > ?
        ''', (token, datetime.datetime.utcnow()))
        
        token_record = cursor.fetchone()
        
        if not token_record:
            return {'error': 'Invalid or expired reset token'}, 400
        
        # Mark token as used
        cursor.execute(
            'UPDATE password_reset_tokens SET used = 1 WHERE id = ?',
            (token_record['id'],)
        )
        
        # Update password
        new_password_hash = hash_password(new_password)
        cursor.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (new_password_hash, token_record['user_id'])
        )
        
        # Get user info for email notification
        cursor.execute('SELECT username, email FROM users WHERE id = ?', (token_record['user_id'],))
        user = cursor.fetchone()
        
        conn.commit()
        
        return {
            'success': True,
            'message': 'Password reset successfully!',
            'username': user['username'],
            'email': user['email']
        }, 200
        
    except Exception as e:
        conn.rollback()
        return {'error': f'Password reset failed: {str(e)}'}, 500
    finally:
        conn.close()


def login_user(email: str, password: str):
    """Login user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Find user
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if not user:
            return {'error': 'Invalid email or password'}, 401
        
        # Verify password
        if not verify_password(password, user['password_hash']):
            return {'error': 'Invalid email or password'}, 401
        
        # Check if email is verified
        if not user['is_verified']:
            return {
                'error': 'Email not verified',
                'message': 'Please verify your email before logging in. Check your inbox for the verification link.',
                'requires_verification': True
            }, 403
        
        # Create token
        token = create_jwt_token(user['id'], user['username'])
        
        return {
            'success': True,
            'message': 'Login successful!',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'is_verified': bool(user['is_verified'])
            },
            'token': token
        }, 200
        
    except Exception as e:
        return {'error': f'Login failed: {str(e)}'}, 500
    finally:
        conn.close()


def get_user_profile(user_id: int):
    """Get user profile"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT id, username, email, is_verified, created_at FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return {'error': 'User not found'}, 404
        
        # Get statistics
        cursor.execute('SELECT COUNT(*) as total FROM stego_history WHERE user_id = ?', (user_id,))
        stats = cursor.fetchone()
        
        return {
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'is_verified': bool(user['is_verified']),
                'created_at': user['created_at'],
                'total_operations': stats['total']
            }
        }, 200
        
    except Exception as e:
        return {'error': str(e)}, 500
    finally:
        conn.close()


def save_stego_history(user_id: int, action: str, filename: str = None, message_preview: str = None):
    """Save steganography operation to history"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Limit message preview to 50 chars
        if message_preview and len(message_preview) > 50:
            message_preview = message_preview[:50] + '...'
        
        cursor.execute(
            'INSERT INTO stego_history (user_id, action, filename, message_preview) VALUES (?, ?, ?, ?)',
            (user_id, action, filename, message_preview)
        )
        conn.commit()
    except Exception as e:
        print(f"Error saving history: {e}")
    finally:
        conn.close()


def get_user_history(user_id: int, limit: int = 20):
    """Get user's steganography history"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'SELECT * FROM stego_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
            (user_id, limit)
        )
        history = cursor.fetchall()
        
        return {
            'history': [dict(row) for row in history]
        }, 200
        
    except Exception as e:
        return {'error': str(e)}, 500
    finally:
        conn.close()


def delete_user(user_id: int, password: str):
    """Delete user and related records after verifying password."""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Find user
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()

        if not user:
            return {'error': 'User not found'}, 404

        # Verify password
        if not verify_password(password, user['password_hash']):
            return {'error': 'Invalid password'}, 401

        # Delete related records
        cursor.execute('DELETE FROM stego_history WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM password_reset_tokens WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM email_verification_tokens WHERE user_id = ?', (user_id,))

        # Delete user
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))

        conn.commit()

        return {
            'success': True,
            'message': 'Account and related data deleted successfully.'
        }, 200

    except Exception as e:
        conn.rollback()
        return {'error': f'Account deletion failed: {str(e)}'}, 500
    finally:
        conn.close()