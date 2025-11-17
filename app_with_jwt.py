from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import hashlib
import os
import jwt
import datetime

app = Flask(__name__)
CORS(app)

# JWT Secret Key (in production, use a secure random key)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ Database initialized!")

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def create_token(user_id):
    """Create JWT token for user"""
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

init_db()
@app.route('/')
def home():
    return 'Stego App Backend with JWT is Running!'

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'success', 
        'message': 'Backend with JWT is running!'
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
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        
        try:
            c.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (data['username'], data['email'], password_hash)
            )
            user_id = c.lastrowid
            conn.commit()
            
            # Create JWT token for the new user
            token = create_token(user_id)
            
            response = {
                'message': 'User registered successfully!',
                'user_id': user_id,
                'username': data['username'],
                'email': data['email'],
                'access_token': token
            }
            
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username or email already exists'}), 409
        finally:
            conn.close()
        
        return jsonify(response), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        password_hash = hash_password(data['password'])
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        
        c.execute('SELECT * FROM users WHERE email = ? AND password_hash = ?', 
                 (data['email'], password_hash))
        user = c.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Invalid email or password'}), 401
        
        user_id, username, email, password_hash, is_verified, created_at = user
        
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



def verify_token(token):
    """Verify JWT token and return user_id"""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/api/protected', methods=['GET'])
def protected():
    """Example protected endpoint that requires JWT token"""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid authorization header'}), 401
    
    token = auth_header.split(' ')[1]
    user_id = verify_token(token)
    
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    # Get user info from database
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('SELECT id, username, email FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user_id, username, email = user
    
    return jsonify({
        'message': 'Access granted to protected endpoint!',
        'user': {
            'id': user_id,
            'username': username,
            'email': email
        }
    }), 200



@app.route('/api/encrypt', methods=['POST'])
def encrypt_message():
    """Encrypt a message into an image - Hadil will implement the logic"""
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
        
        if not data or not data.get('image_path') or not data.get('message'):
            return jsonify({'error': 'image_path and message are required'}), 400
        
        # This is where Hadil's encryption logic will go
        # For now, return a placeholder response
        response = {
            'message': 'Encryption endpoint ready for Hadil',
            'encrypted_image_path': f"/output/encrypted_{user_id}.png",
            'original_message': data['message'],
            'status': 'pending_implementation',
            'note': 'Hadil will implement the actual steganography here'
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_message():
    """Decrypt a message from an image - Hadil will implement the logic"""
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
        
        if not data or not data.get('image_path'):
            return jsonify({'error': 'image_path is required'}), 400
        
        # This is where Hadil's decryption logic will go
        # For now, return a placeholder response
        response = {
            'message': 'Decryption endpoint ready for Hadil',
            'decrypted_message': 'SAMPLE_DECRYPTED_TEXT',
            'image_path': data['image_path'],
            'status': 'pending_implementation', 
            'note': 'Hadil will implement the actual steganography here'
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500




if __name__ == '__main__':
    print("🚀 Starting Stego App Backend with JWT...")
    print("📍 Available endpoints:")
    print("   POST http://localhost:5000/api/register")
    print("   POST http://localhost:5000/api/login")
    print("   " + "="*50)
    print("   🔐 Now with JWT Token Authentication!")
    print("   " + "="*50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
