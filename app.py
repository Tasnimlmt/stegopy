
from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS
from flask_mail import Mail, Message
import sqlite3
import hashlib
import os
import jwt
import datetime
import secrets
import threading
import time
import requests

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'test2@example.com'  # Change this
app.config['MAIL_PASSWORD'] = 'fake-password'     # Change this
app.config['MAIL_DEFAULT_SENDER'] = 'test2@example.com'

mail = Mail(app)



def init_db():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_verified BOOLEAN DEFAULT 0,
            verification_token TEXT,
            profile_image TEXT, 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ Database initialized!")




def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def create_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except:
        return None

def generate_verification_token():
    return secrets.token_urlsafe(32)

def send_verification_email(user_email, verification_token, username):
    verification_url = f"http://localhost:5000/api/verify-email?token={verification_token}"
    
    # FAKE EMAIL SYSTEM - Development mode
    print("=" * 60)
    print("📧 VERIFICATION EMAIL (Development Mode)")
    print(f"To: {user_email}")
    print(f"Username: {username}")
    print(f"📎 Verification URL: {verification_url}")
    print("=" * 60)
    
    return True  # Always return True for development

def auto_verify_user(user_id):
    """Auto-verify user for testing"""
    def verify():
        time.sleep(2)  # Wait 2 seconds
        try:
            # Get the verification token from database
            conn = sqlite3.connect('app.db')
            c = conn.cursor()
            c.execute('SELECT verification_token FROM users WHERE id = ?', (user_id,))
            result = c.fetchone()
            conn.close()
            
            if result and result[0]:
                token = result[0]
                # Auto-verify
                verify_response = requests.get(f"http://localhost:5000/api/verify-email?token={token}")
                if verify_response.status_code == 200:
                    print(f"✅ Auto-verified user {user_id}")
                else:
                    print(f"❌ Auto-verify failed for user {user_id}")
        except Exception as e:
            print(f"❌ Auto-verify error: {e}")
    
    thread = threading.Thread(target=verify)
    thread.daemon = True
    thread.start()

init_db()

@app.route('/')
def home():
    return 'Stego App with Email Verification is Running!'

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'success', 
        'message': 'Backend with email verification is running!'
    })

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Username, email and password are required'}), 400
        
        if len(data['password']) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        password_hash = hash_password(data['password'])
        verification_token = generate_verification_token()
        
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        
        try:
            c.execute(
                'INSERT INTO users (username, email, password_hash, verification_token) VALUES (?, ?, ?, ?)',
                (data['username'], data['email'], password_hash, verification_token)
            )
            user_id = c.lastrowid
            conn.commit()
            
            # Send verification email
            email_sent = send_verification_email(data['email'], verification_token, data['username'])
            
            # Auto-verify for testing
            auto_verify_user(user_id)
            
            # Create JWT token
            token = create_token(user_id)
            
            response = {
                'message': 'User registered successfully! Please check your email for verification.',
                'user_id': user_id,
                'username': data['username'],
                'email': data['email'],
                'access_token': token,
                'email_sent': email_sent
            }
            
            if not email_sent:
                response['warning'] = 'Failed to send verification email'
            
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username or email already exists'}), 409
        finally:
            conn.close()
        
        return jsonify(response), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify-email', methods=['GET'])
def verify_email():
    token = request.args.get('token')
    
    if not token:
        return jsonify({'error': 'Verification token is required'}), 400
    
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    
    c.execute('SELECT id, username FROM users WHERE verification_token = ?', (token,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Invalid verification token'}), 400
    
    user_id, username = user
    
    # Mark user as verified and clear token
    c.execute('UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({
        'message': f'Email verified successfully! Welcome {username}!',
        'user_id': user_id,
        'username': username
    }), 200

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        password_hash = hash_password(data['password'])
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        
        # c.execute('SELECT * FROM users WHERE email = ? AND password_hash = ?', 
        c.execute('SELECT id, username, email, password_hash, is_verified, verification_token, profile_image, created_at FROM users WHERE email = ? AND password_hash = ?', (data['email'], password_hash))
                #  (data['email'], password_hash))
        user = c.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Invalid email or password'}), 401
        

        user_id, username, email, password_hash, is_verified, verification_token, profile_image, created_at = user

        # user_id, username, email, password_hash, is_verified, verification_token, created_at = user
        
        # Check if email is verified
        if not is_verified:
            return jsonify({
                'error': 'Email not verified. Please check your email for verification link.',
                'needs_verification': True
            }), 403
        
        # Create JWT token
        token = create_token(user_id)
        
        return jsonify({
            'message': 'Login successful!',
            'access_token': token,
            'user': {
                'id': user_id,
                'username': username,
                'email': email,
                'is_verified': bool(is_verified)
            }
        }), 200
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/resend-verification', methods=['POST'])
def resend_verification():
    """Resend verification email"""
    try:
        data = request.get_json()
        
        if not data or not data.get('email'):
            return jsonify({'error': 'Email is required'}), 400
        
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        
        c.execute('SELECT id, username, is_verified, verification_token FROM users WHERE email = ?', (data['email'],))
        user = c.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'Email not found'}), 404
        
        user_id, username, is_verified, verification_token = user
        
        if is_verified:
            conn.close()
            return jsonify({'message': 'Email is already verified'}), 200
        
        # Generate new token if needed
        if not verification_token:
            verification_token = generate_verification_token()
            c.execute('UPDATE users SET verification_token = ? WHERE id = ?', (verification_token, user_id))
            conn.commit()
        
        # Resend verification email
        email_sent = send_verification_email(data['email'], verification_token, username)
        
        conn.close()
        
        response = {
            'message': 'Verification email sent successfully!',
            'email_sent': email_sent
        }
        
        if not email_sent:
            response['warning'] = 'Failed to send verification email'
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """Send password reset email"""
    try:
        data = request.get_json()
        
        if not data or not data.get('email'):
            return jsonify({'error': 'Email is required'}), 400
        
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        
        c.execute('SELECT id, username FROM users WHERE email = ?', (data['email'],))
        user = c.fetchone()
        
        if not user:
            conn.close()
            # Don't reveal if email exists or not
            return jsonify({
                'message': 'If the email exists, a password reset link has been sent.'
            }), 200
        
        user_id, username = user
        reset_token = generate_verification_token()
        
        # Save reset token to database
        c.execute('UPDATE users SET verification_token = ? WHERE id = ?', (reset_token, user_id))
        conn.commit()
        conn.close()
        
        # For development: print reset link to console
        reset_url = f"http://localhost:5000/api/reset-password?token={reset_token}"
        print("=" * 60)
        print("🔐 PASSWORD RESET EMAIL (Development Mode)")
        print(f"To: {data['email']}")
        print(f"Username: {username}")
        print(f"📎 Reset URL: {reset_url}")
        print("=" * 60)
        
        return jsonify({
            'message': 'If the email exists, a password reset link has been sent.',
            'reset_url': reset_url  # For development testing
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Reset password with token"""
    try:
        data = request.get_json()
        
        if not data or not data.get('token') or not data.get('new_password'):
            return jsonify({'error': 'Token and new password are required'}), 400
        
        if len(data['new_password']) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        
        c.execute('SELECT id FROM users WHERE verification_token = ?', (data['token'],))
        user = c.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'Invalid or expired reset token'}), 400
        
        user_id = user[0]
        new_password_hash = hash_password(data['new_password'])
        
        # Update password and clear reset token
        c.execute('UPDATE users SET password_hash = ?, verification_token = NULL WHERE id = ?', 
                 (new_password_hash, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Password reset successfully! You can now login with your new password.'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500




@app.route('/api/profile', methods=['GET'])
def get_profile():
    """Get user profile"""
    # Check JWT token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authentication required'}), 401
    
    token = auth_header.split(' ')[1]
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('SELECT id, username, email, is_verified, profile_image, created_at FROM users WHERE id = ?', (user_id,))
    # c.execute('SELECT id, username, email, is_verified, created_at FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # user_id, username, email, is_verified, created_at = user
    user_id, username, email, is_verified, profile_image, created_at = user




    return jsonify({
    'user': {
        'id': user_id,
        'username': username,
        'email': email,
        'is_verified': bool(is_verified),
        'profile_image': profile_image,
        'created_at': created_at
        }
    }), 200






@app.route('/api/profile', methods=['PUT'])
def update_profile():
    """Update user profile"""
    # Check JWT token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authentication required'}), 401
    
    token = auth_header.split(' ')[1]
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        
        updates = []
        params = []
        
        # Update username if provided
        if data.get('username'):
            # Check if username is already taken by another user
            c.execute('SELECT id FROM users WHERE username = ? AND id != ?', (data['username'], user_id))
            if c.fetchone():
                conn.close()
                return jsonify({'error': 'Username already taken'}), 409
            updates.append('username = ?')
            params.append(data['username'])
        
        # Update email if provided
        if data.get('email'):
            # Check if email is already taken by another user
            c.execute('SELECT id FROM users WHERE email = ? AND id != ?', (data['email'], user_id))
            if c.fetchone():
                conn.close()
                return jsonify({'error': 'Email already registered'}), 409
            updates.append('email = ?')
            updates.append('is_verified = 0')  # Require re-verification if email changes
            params.append(data['email'])
        
        if not updates:
            conn.close()
            return jsonify({'error': 'No valid fields to update'}), 400
        
        # Add user_id to params
        params.append(user_id)
        
        # Build and execute update query
        query = f'UPDATE users SET {", ".join(updates)} WHERE id = ?'
        c.execute(query, params)
        conn.commit()
        
        # Get updated user data
        c.execute('SELECT id, username, email, is_verified FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        conn.close()
        
        user_id, username, email, is_verified = user
        
        return jsonify({
            'message': 'Profile updated successfully!',
            'user': {
                'id': user_id,
                'username': username,
                'email': email,
                'is_verified': bool(is_verified)
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/change-password', methods=['POST'])
def change_password():
    """Change user password"""
    # Check JWT token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authentication required'}), 401
    
    token = auth_header.split(' ')[1]
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    try:
        data = request.get_json()
        
        if not data or not data.get('current_password') or not data.get('new_password'):
            return jsonify({'error': 'Current password and new password are required'}), 400
        
        if len(data['new_password']) < 6:
            return jsonify({'error': 'New password must be at least 6 characters'}), 400
        
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        
        # Verify current password
        current_password_hash = hash_password(data['current_password'])
        c.execute('SELECT id FROM users WHERE id = ? AND password_hash = ?', (user_id, current_password_hash))
        user = c.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Update to new password
        new_password_hash = hash_password(data['new_password'])
        c.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Password changed successfully!'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500





@app.route('/api/encrypt', methods=['POST'])
def encrypt_message():
    """Encrypt a message into an image - HADIL WILL IMPLEMENT"""
    # Check JWT token first
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authentication required'}), 401
    
    token = auth_header.split(' ')[1]
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    try:
        data = request.get_json()
        
        # Validate input
        if not data or not data.get('image_data') or not data.get('secret_message'):
            return jsonify({'error': 'image_data and secret_message are required'}), 400
        
        # THIS IS WHERE HADIL'S CODE WILL GO
        # For now, return a placeholder response
        response = {
            'message': 'Encryption endpoint ready for Hadil',
            'status': 'pending_implementation',
            'encrypted_image': 'ENCRYPTED_IMAGE_DATA_PLACEHOLDER',
            'note': 'Hadil will implement steganography encryption here'
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_message():
    """Decrypt a message from an image - HADIL WILL IMPLEMENT"""
    # Check JWT token first
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authentication required'}), 401
    
    token = auth_header.split(' ')[1]
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    try:
        data = request.get_json()
        
        # Validate input
        if not data or not data.get('encrypted_image'):
            return jsonify({'error': 'encrypted_image is required'}), 400
        
        # THIS IS WHERE HADIL'S CODE WILL GO
        # For now, return a placeholder response
        response = {
            'message': 'Decryption endpoint ready for Hadil',
            'status': 'pending_implementation',
            'decrypted_message': 'SECRET_MESSAGE_PLACEHOLDER',
            'note': 'Hadil will implement steganography decryption here'
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500







import os
from werkzeug.utils import secure_filename

# Configure upload settings
app.config['UPLOAD_FOLDER'] = 'uploads/profile_images'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB limit
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/upload-profile-image', methods=['POST'])
def upload_profile_image():
    """Upload profile image"""
    # Check JWT token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authentication required'}), 401
    
    token = auth_header.split(' ')[1]
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    try:
        # Check if file was uploaded
        if 'profile_image' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['profile_image']
        
        # Check if file is selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Check file type
        if not allowed_file(file.filename):
            return jsonify({'error': 'Allowed file types: png, jpg, jpeg, gif'}), 400
        
        # Generate secure filename
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        filename = f"user_{user_id}.{file_extension}"
        filename = secure_filename(filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save file
        file.save(filepath)
        
        # Update database
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        c.execute('UPDATE users SET profile_image = ? WHERE id = ?', (filename, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Profile image uploaded successfully!',
            'filename': filename
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/profile-image/<user_id>', methods=['GET'])
def get_profile_image(user_id):
    """Get profile image"""
    try:
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        c.execute('SELECT profile_image FROM users WHERE id = ?', (user_id,))
        result = c.fetchone()
        conn.close()
        
        if not result or not result[0]:
            return jsonify({'error': 'Profile image not found'}), 404
        
        filename = result[0]
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'Image file not found'}), 404
        
        # For now, return filename - frontend will handle display
        return jsonify({
            'profile_image': filename,
            'image_url': f"/api/profile-image/{user_id}"
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500









if __name__ == '__main__':
    print("🚀 Starting Stego App with Email Verification...")
    print("📍 Available endpoints:")
    print("   POST /api/register - Register with email verification")
    print("   GET  /api/verify-email - Verify email")
    print("   POST /api/login - Login (requires verification)")
    print("   POST /api/resend-verification - Resend verification email")
    print("   POST /api/forgot-password - Request password reset")
    print("   POST /api/reset-password - Reset password with token")
    print("   " + "="*50)
    print("   📧 Email verification system active!")
    print("   🔐 Password reset system active!")
    print("   ⚡ Auto-verification for testing!")
    print("   " + "="*50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)