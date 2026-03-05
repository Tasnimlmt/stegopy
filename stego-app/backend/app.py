from flask_cors import CORS
import os
import sys
import json
import io
from flask import Flask, request, jsonify, render_template

# Add parent directory to path
sys.path.insert(0, os.path.dirname(__file__))

from stego.stego import (
    hide_message_advanced,
    extract_message_advanced,
    image_from_base64,
    image_to_base64,
    ShamirSecretSharing,
    MultiCarrierStego,
    AdvancedStegoEngine          # NEW: needed for share encryption/decryption
)

from database import (
    init_database, 
    register_user, 
    login_user, 
    get_user_profile,
    get_user_history,
    save_stego_history,
    delete_user,
    token_required,
    verify_email,
    resend_verification_email,
    request_password_reset,
    verify_reset_token,
    reset_password
)

from email_utils import (
    send_verification_email,
    send_password_reset_email,
    send_password_changed_notification
)

app = Flask(__name__, 
            template_folder='../frontend/templates',
            static_folder='../frontend/static')
CORS(app)

# Configuration
app.config['UPLOAD_FOLDER'] = '../uploads/stego_images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database on startup
init_database()


# ==================== PUBLIC ROUTES ====================

@app.route('/')
def index():
    """Serve main page"""
    return render_template('index.html')


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'success',
        'message': 'Advanced Steganography API is running!',
        'version': '3.1.0',
        'features': [
            'authentication',
            'email_verification',
            'password_reset',
            'history',
            'jwt',
            'deniable_steganography',
            'duress_passwords',
            'shamirs_secret_sharing',
            'post_quantum_encryption',
            'multi_carrier_support'
        ]
    })


# ==================== AUTHENTICATION ROUTES ====================

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    """Register new user with email verification"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        result, status = register_user(username, email, password)
        
        # Send verification email if registration successful
        if status == 201 and result.get('success'):
            verification_token = result.get('verification_token')
            email_sent = send_verification_email(email, username, verification_token)
            
            if email_sent:
                result['email_sent'] = True
            else:
                result['email_sent'] = False
                result['warning'] = 'Account created but verification email failed to send. Please request a new one.'
        
        return jsonify(result), status
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/auth/verify-email', methods=['POST'])
def api_verify_email():
    """Verify email with token"""
    try:
        data = request.get_json()
        
        if not data or not data.get('token'):
            return jsonify({'error': 'Verification token is required'}), 400
        
        token = data.get('token')
        result, status = verify_email(token)
        
        return jsonify(result), status
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/auth/resend-verification', methods=['POST'])
def api_resend_verification():
    """Resend verification email"""
    try:
        data = request.get_json()
        
        if not data or not data.get('email'):
            return jsonify({'error': 'Email is required'}), 400
        
        email = data.get('email')
        result, status = resend_verification_email(email)
        
        # Send email if successful
        if status == 200 and result.get('success'):
            verification_token = result.get('verification_token')
            username = result.get('username')
            email_sent = send_verification_email(email, username, verification_token)
            
            if not email_sent:
                return jsonify({'error': 'Failed to send verification email'}), 500
        
        return jsonify(result), status
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/auth/forgot-password', methods=['POST'])
def api_forgot_password():
    """Request password reset"""
    try:
        data = request.get_json()
        
        if not data or not data.get('email'):
            return jsonify({'error': 'Email is required'}), 400
        
        email = data.get('email')
        result, status = request_password_reset(email)
        
        # Send reset email if successful
        if status == 200 and result.get('success'):
            reset_token = result.get('reset_token')
            username = result.get('username')
            
            if reset_token and username:  # Only send if user exists
                email_sent = send_password_reset_email(email, username, reset_token)
                
                if not email_sent:
                    print(f"Failed to send password reset email to {email}")
        
        # Always return success (security - don't reveal if email exists)
        return jsonify({
            'success': True,
            'message': 'If that email exists, a password reset link has been sent.'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/auth/verify-reset-token', methods=['POST'])
def api_verify_reset_token():
    """Verify if reset token is valid"""
    try:
        data = request.get_json()
        
        if not data or not data.get('token'):
            return jsonify({'error': 'Reset token is required'}), 400
        
        token = data.get('token')
        result, status = verify_reset_token(token)
        
        return jsonify(result), status
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/auth/reset-password', methods=['POST'])
def api_reset_password():
    """Reset password with token"""
    try:
        data = request.get_json()
        
        if not data or not data.get('token') or not data.get('new_password'):
            return jsonify({'error': 'Token and new password are required'}), 400
        
        token = data.get('token')
        new_password = data.get('new_password')
        
        result, status = reset_password(token, new_password)
        
        # Send confirmation email if successful
        if status == 200 and result.get('success'):
            email = result.get('email')
            username = result.get('username')
            send_password_changed_notification(email, username)
        
        return jsonify(result), status
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """Login user"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        result, status = login_user(email, password)
        return jsonify(result), status
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/auth/profile', methods=['GET'])
@token_required
def api_get_profile(current_user):
    """Get current user's profile (protected route)"""
    try:
        result, status = get_user_profile(current_user['user_id'])
        return jsonify(result), status
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/auth/history', methods=['GET'])
@token_required
def api_get_history(current_user):
    """Get current user's steganography history (protected route)"""
    try:
        limit = request.args.get('limit', 20, type=int)
        result, status = get_user_history(current_user['user_id'], limit)
        return jsonify(result), status
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/auth/delete', methods=['POST'])
@token_required
def api_delete_account(current_user):
    """Delete the authenticated user's account after password confirmation."""
    try:
        data = request.get_json()

        if not data or not data.get('password'):
            return jsonify({'error': 'Password is required'}), 400

        password = data.get('password')

        result, status = delete_user(current_user['user_id'], password)

        # On successful deletion, the frontend should clear local auth state
        return jsonify(result), status

    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


# ==================== ADVANCED STEGANOGRAPHY ROUTES ====================

@app.route('/api/hide', methods=['POST'])
@token_required
def api_hide_message(current_user):
    """
    Hide message in image with advanced features
    
    Request JSON:
    {
        "image": "base64_image_data",
        "message": "secret message",
        "password": "encryption_password",
        "options": {
            "mode": "standard|deniable|duress",
            "compress": true,
            "use_pq": false,
            "decoy_messages": [["decoy1", "pass1"], ["decoy2", "pass2"]],
            "duress_message": "fake message",
            "duress_password": "panic_pass",
            "destroy_on_duress": false
        }
    }
    """
    try:
        data = request.get_json()
        
        # Validate input
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if not data.get('image'):
            return jsonify({'error': 'Image data is required'}), 400
        
        if not data.get('message'):
            return jsonify({'error': 'Message is required'}), 400
        
        if not data.get('password'):
            return jsonify({'error': 'Password is required'}), 400
        
        # Parse options
        options = data.get('options', {})
        
        # Convert base64 to image
        image = image_from_base64(data['image'])
        
        # Hide message with advanced features
        stego_image = hide_message_advanced(
            image, 
            data['message'], 
            data['password'],
            options
        )
        
        # Convert back to base64
        result_base64 = image_to_base64(stego_image)
        
        # Prepare history entry
        mode = options.get('mode', 'standard')
        action_desc = f"hide_{mode}"
        
        # Save to history
        save_stego_history(
            user_id=current_user['user_id'],
            action=action_desc,
            filename=f"stego_{current_user['username']}.png",
            message_preview=data['message']
        )
        
        return jsonify({
            'success': True,
            'message': f'Message hidden successfully using {mode} mode!',
            'image': result_base64,
            'stats': {
                'original_message_length': len(data['message']),
                'image_size': f"{stego_image.width}x{stego_image.height}",
                'max_capacity': f"{(stego_image.width * stego_image.height * 3) // 8} bytes",
                'mode': mode,
                'compressed': options.get('compress', True),
                'pq_protected': options.get('use_pq', False)
            },
            'user': current_user['username']
        }), 200
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/extract', methods=['POST'])
@token_required
def api_extract_message(current_user):
    """
    Extract message from image with advanced features
    
    Request JSON:
    {
        "image": "base64_image_data",
        "password": "decryption_password"
    }
    """
    try:
        data = request.get_json()
        
        # Validate input
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if not data.get('image'):
            return jsonify({'error': 'Image data is required'}), 400
        
        if not data.get('password'):
            return jsonify({'error': 'Password is required'}), 400
        
        # Convert base64 to image
        image = image_from_base64(data['image'])
        
        # Extract message with advanced features
        result = extract_message_advanced(image, data['password'])
        
        message = result['message']
        mode = result.get('mode', 'standard')
        
        # Save to history
        action_desc = f"extract_{mode}"
        if mode == 'duress' and result.get('is_duress'):
            action_desc = "extract_duress_activated"
        elif mode == 'deniable' and result.get('is_decoy'):
            action_desc = "extract_decoy"
        
        save_stego_history(
            user_id=current_user['user_id'],
            action=action_desc,
            message_preview=message
        )
        
        return jsonify({
            'success': True,
            'message': message,
            'metadata': {
                'mode': mode,
                'is_duress': result.get('is_duress', False),
                'is_decoy': result.get('is_decoy', False),
                'layer': result.get('layer', 'standard')
            },
            'user': current_user['username']
        }), 200
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


# ==================== SHAMIR SECRET SHARING ROUTES ====================

@app.route('/api/sss/split', methods=['POST'])
@token_required
def api_split_secret(current_user):
    """
    Split secret using Shamir's Secret Sharing with password-protected shares.

    Request JSON:
    {
        "secret": "message to split",
        "k": 3,
        "n": 5,
        "password": "share_encryption_password",   <-- NEW (required)
        "images": ["base64_img1", "base64_img2", ...]
    }

    Each share's (x, y) coordinate is encrypted with the provided password
    before being embedded in its carrier image.  The same password must be
    supplied when reconstructing.
    """
    try:
        data = request.get_json()
        
        secret = data.get('secret')
        k = data.get('k', 3)
        n = data.get('n', 5)
        password = data.get('password')          # NEW
        images_base64 = data.get('images', [])
        
        if not secret:
            return jsonify({'error': 'Secret is required'}), 400

        if not password:
            return jsonify({'error': 'Password is required to protect share images'}), 400
        
        if len(images_base64) < n:
            return jsonify({'error': f'Need {n} images for {n} shares'}), 400
        
        # Split secret into Shamir shares
        secret_bytes = secret.encode()
        shares = ShamirSecretSharing.split_secret(secret_bytes, k, n)
        
        # Embed each share – coordinates are encrypted before embedding
        result_images = []
        for i, (x, y) in enumerate(shares):
            # Wrap coordinates in JSON then encrypt with the user's password
            share_json = json.dumps({'x': x, 'y': y, 'share_index': i + 1})
            encrypted_share = AdvancedStegoEngine.encrypt_text(
                share_json, password, compress=False
            )
            share_payload = json.dumps(encrypted_share)

            image = image_from_base64(images_base64[i])
            stego_image = MultiCarrierStego.embed_in_image(image, share_payload)
            result_images.append(image_to_base64(stego_image))
        
        # Save to history
        save_stego_history(
            user_id=current_user['user_id'],
            action='sss_split',
            filename=f"sss_{k}_of_{n}.png",
            message_preview=f"Split into {n} shares, need {k}"
        )
        
        return jsonify({
            'success': True,
            'message': f'Secret split into {n} shares (need {k} to reconstruct)',
            'shares': result_images,
            'k': k,
            'n': n
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/sss/reconstruct', methods=['POST'])
@token_required
def api_reconstruct_secret(current_user):
    """
    Reconstruct secret from password-protected share images.

    Request JSON:
    {
        "images": ["base64_img1", "base64_img2", ...],
        "password": "share_encryption_password",   <-- NEW (required)
        "secret_length": 32
    }

    Each share image is extracted then decrypted with the password before
    Shamir reconstruction runs.  A wrong password returns a clear error
    rather than silently producing garbage output.
    """
    try:
        data = request.get_json()
        
        images_base64 = data.get('images', [])
        password = data.get('password')          # NEW
        secret_length = data.get('secret_length', 32)
        
        if len(images_base64) < 2:
            return jsonify({'error': 'Need at least 2 share images'}), 400

        if not password:
            return jsonify({'error': 'Password is required to decrypt share images'}), 400
        
        # Extract and decrypt shares from images
        shares = []
        for idx, img_base64 in enumerate(images_base64):
            image = image_from_base64(img_base64)
            raw_payload = MultiCarrierStego.extract_from_image(image)

            try:
                encrypted_share = json.loads(raw_payload)
                share_json = AdvancedStegoEngine.decrypt_text(encrypted_share, password)
                share_data = json.loads(share_json)
                x = share_data['x']
                y = share_data['y']
            except Exception:
                return jsonify({
                    'error': f'Wrong password or corrupted share (image {idx + 1})'
                }), 400

            shares.append((x, y))
        
        # Reconstruct secret using Lagrange interpolation
        secret_bytes = ShamirSecretSharing.reconstruct_secret(shares, secret_length)
        secret = secret_bytes.decode().rstrip('\x00')
        
        # Save to history
        save_stego_history(
            user_id=current_user['user_id'],
            action='sss_reconstruct',
            message_preview=f"Reconstructed from {len(shares)} shares"
        )
        
        return jsonify({
            'success': True,
            'secret': secret,
            'shares_used': len(shares)
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


# ==================== CARRIER INFO ROUTE ====================

@app.route('/api/carrier/info', methods=['POST'])
@token_required
def api_carrier_info(current_user):
    """
    Get carrier capacity information
    
    Request JSON:
    {
        "image": "base64_image_data"
    }
    """
    try:
        data = request.get_json()
        
        if not data.get('image'):
            return jsonify({'error': 'Image data is required'}), 400
        
        # Convert base64 to image
        image = image_from_base64(data['image'])
        
        # Get capacity info
        buffered = io.BytesIO()
        image.save(buffered, format="PNG")
        image_bytes = buffered.getvalue()
        
        info = MultiCarrierStego.get_carrier_info(image_bytes, 'image')
        
        return jsonify({
            'success': True,
            'carrier_info': info
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


# ==================== DEMO ROUTES (No Auth Required) ====================

@app.route('/api/demo/hide', methods=['POST'])
def api_demo_hide():
    """Demo endpoint - hide without authentication"""
    try:
        data = request.get_json()
        
        if not data or not data.get('image') or not data.get('message') or not data.get('password'):
            return jsonify({'error': 'Image, message, and password are required'}), 400
        
        image = image_from_base64(data['image'])
        options = data.get('options', {})
        stego_image = hide_message_advanced(image, data['message'], data['password'], options)
        result_base64 = image_to_base64(stego_image)
        
        return jsonify({
            'success': True,
            'message': 'Message hidden successfully! (Demo mode - login for history)',
            'image': result_base64
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/demo/extract', methods=['POST'])
def api_demo_extract():
    """Demo endpoint - extract without authentication"""
    try:
        data = request.get_json()
        
        if not data or not data.get('image') or not data.get('password'):
            return jsonify({'error': 'Image and password are required'}), 400
        
        image = image_from_base64(data['image'])
        result = extract_message_advanced(image, data['password'])
        
        return jsonify({
            'success': True,
            'message': result['message'],
            'metadata': {
                'mode': result.get('mode', 'standard'),
                'is_duress': result.get('is_duress', False),
                'is_decoy': result.get('is_decoy', False)
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("=" * 70)
    print("🚀 ADVANCED STEGANOGRAPHY API SERVER")
    print("=" * 70)
    print("📍 Server running at: http://localhost:5000")
    print("📍 Authentication Endpoints:")
    print("   POST /api/auth/register")
    print("   POST /api/auth/verify-email")
    print("   POST /api/auth/resend-verification")
    print("   POST /api/auth/login")
    print("   POST /api/auth/forgot-password")
    print("   POST /api/auth/verify-reset-token")
    print("   POST /api/auth/reset-password")
    print("   GET  /api/auth/profile (protected)")
    print("   GET  /api/auth/history (protected)")
    print("📍 Steganography Endpoints:")
    print("   POST /api/hide (protected) - Advanced hiding with multiple modes")
    print("   POST /api/extract (protected) - Extract with mode detection")
    print("   POST /api/sss/split (protected) - Shamir's Secret Sharing split")
    print("   POST /api/sss/reconstruct (protected) - Reconstruct from shares")
    print("   POST /api/carrier/info (protected) - Get carrier capacity info")
    print("   POST /api/demo/hide (public demo)")
    print("   POST /api/demo/extract (public demo)")
    print("📍 Advanced Features:")
    print("   ✓ Email Verification")
    print("   ✓ Password Reset")
    print("   ✓ Deniable Steganography (multi-layer)")
    print("   ✓ Duress/Panic Passwords")
    print("   ✓ Shamir's Secret Sharing (password-protected shares)")
    print("   ✓ Post-Quantum Hybrid Encryption")
    print("   ✓ Multi-Carrier Support (Image/Audio)")
    print("=" * 70)
    
    # Choose port: respect PORT env var, otherwise try 5000 and fall back
    # to any available port if 5000 is already in use.
    import socket

    def _find_free_port(preferred=5000):
        # Try preferred port first
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', preferred))
            port = s.getsockname()[1]
            s.close()
            return port
        except OSError:
            # Preferred not available, bind to port 0 to get an ephemeral port
            s.close()
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.bind(('0.0.0.0', 0))
            port = s2.getsockname()[1]
            s2.close()
            return port

    env_port = os.environ.get('PORT')
    try:
        port = int(env_port) if env_port else _find_free_port(5000)
    except Exception:
        port = _find_free_port(5000)

    print(f"Starting server on port: {port}")
    app.run(debug=True, host='0.0.0.0', port=port)