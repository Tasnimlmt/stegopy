from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import hashlib
import os

app = Flask(__name__)
CORS(app)

# Initialize database
def init_db():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    
    # Create users table
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

# Simple password hashing (for development only!)
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Initialize database when app starts
init_db()

@app.route('/')
def home():
    return 'Stego App Backend is Running!'

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'success', 
        'message': 'Backend is running with database!'
    })

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Username, email and password are required'}), 400
        
        if len(data['password']) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        # Hash password (simple version for development)
        password_hash = hash_password(data['password'])
        
        # Save to database
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        
        try:
            c.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (data['username'], data['email'], password_hash)
            )
            user_id = c.lastrowid
            conn.commit()
            
            response = {
                'message': 'User registered successfully!',
                'user_id': user_id,
                'username': data['username'],
                'email': data['email']
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
        
        # Hash the provided password
        password_hash = hash_password(data['password'])
        
        # Find user in database
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        
        c.execute('SELECT * FROM users WHERE email = ? AND password_hash = ?', (data['email'], password_hash))
        user = c.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Invalid email or password'}), 401
        
        user_id, username, email, password_hash, is_verified, created_at = user
        
        return jsonify({
            'message': 'Login successful!',
            'user': {
                'id': user_id,
                'username': username,
                'email': email,
                'is_verified': bool(is_verified)
            }
        }), 200
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting Stego App Backend (Development Version)...")
    print("📍 Available endpoints:")
    print("   GET  http://localhost:5000/")
    print("   GET  http://localhost:5000/api/health") 
    print("   POST http://localhost:5000/api/register")
    print("   POST http://localhost:5000/api/login")
    print("   " + "="*50)
    print("   ⚠️  Using simple password hashing for development")
    print("   ✅ Backend ready for testing!")
    print("   " + "="*50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
