import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Email configuration - Update these with your SMTP settings
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', 'your-email@gmail.com')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', 'your-app-password')
FROM_EMAIL = os.getenv('FROM_EMAIL', 'noreply@stego-app.com')
APP_NAME = "Advanced Steganography"
APP_URL = os.getenv('APP_URL', 'http://localhost:5000')

# Debug mode - set to True to see detailed error messages
DEBUG_EMAIL = os.getenv('DEBUG_EMAIL', 'True').lower() == 'true'


def send_email(to_email: str, subject: str, html_body: str, text_body: str = None):
    """Send email using SMTP"""
    try:
        # Validate configuration
        if SMTP_USERNAME == 'your-email@gmail.com' or SMTP_PASSWORD == 'your-app-password':
            error_msg = "Email not configured! Please set SMTP_USERNAME and SMTP_PASSWORD in .env file"
            print(f"❌ EMAIL ERROR: {error_msg}")
            if DEBUG_EMAIL:
                print(f"Current SMTP_USERNAME: {SMTP_USERNAME}")
                print(f"Please check your .env file or environment variables")
            return False
        
        if DEBUG_EMAIL:
            print(f"📧 Attempting to send email to: {to_email}")
            print(f"📧 Using SMTP server: {SMTP_SERVER}:{SMTP_PORT}")
            print(f"📧 From: {FROM_EMAIL}")
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = FROM_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Add text version (fallback)
        if text_body:
            part1 = MIMEText(text_body, 'plain')
            msg.attach(part1)
        
        # Add HTML version
        part2 = MIMEText(html_body, 'html')
        msg.attach(part2)
        
        # Send email
        if DEBUG_EMAIL:
            print(f"📧 Connecting to SMTP server...")
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            if DEBUG_EMAIL:
                print(f"📧 Starting TLS...")
            server.starttls()
            
            if DEBUG_EMAIL:
                print(f"📧 Logging in with username: {SMTP_USERNAME}")
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            
            if DEBUG_EMAIL:
                print(f"📧 Sending message...")
            server.send_message(msg)
        
        if DEBUG_EMAIL:
            print(f"✅ Email sent successfully to {to_email}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        error_msg = f"SMTP Authentication failed. Check your username/password. Error: {str(e)}"
        print(f"❌ EMAIL ERROR: {error_msg}")
        if DEBUG_EMAIL:
            print(f"💡 TIP: For Gmail, you need an 'App Password', not your regular password")
            print(f"💡 Generate one at: https://myaccount.google.com/apppasswords")
        return False
        
    except smtplib.SMTPException as e:
        error_msg = f"SMTP error occurred: {str(e)}"
        print(f"❌ EMAIL ERROR: {error_msg}")
        return False
        
    except ConnectionRefusedError as e:
        error_msg = f"Connection refused. Check SMTP_SERVER and SMTP_PORT. Error: {str(e)}"
        print(f"❌ EMAIL ERROR: {error_msg}")
        if DEBUG_EMAIL:
            print(f"💡 Make sure your firewall allows connections to {SMTP_SERVER}:{SMTP_PORT}")
        return False
        
    except Exception as e:
        error_msg = f"Unexpected error sending email: {str(e)}"
        print(f"❌ EMAIL ERROR: {error_msg}")
        if DEBUG_EMAIL:
            import traceback
            print("Full traceback:")
            traceback.print_exc()
        return False


def send_verification_email(to_email: str, username: str, verification_token: str):
    """Send email verification email"""
    verification_url = f"{APP_URL}?token={verification_token}"
    
    subject = f"Verify your {APP_NAME} account"
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }}
            .container {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 30px;
                border-radius: 10px;
                color: white;
            }}
            .content {{
                background: white;
                color: #333;
                padding: 30px;
                border-radius: 8px;
                margin-top: 20px;
            }}
            .button {{
                display: inline-block;
                padding: 12px 30px;
                background: #667eea;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                margin: 20px 0;
                font-weight: bold;
            }}
            .footer {{
                margin-top: 30px;
                font-size: 12px;
                color: #666;
                text-align: center;
            }}
            .warning {{
                background: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 15px;
                margin: 20px 0;
                border-radius: 4px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 {APP_NAME}</h1>
            <div class="content">
                <h2>Welcome, {username}! 👋</h2>
                <p>Thank you for registering with {APP_NAME}. We're excited to have you on board!</p>
                <p>To complete your registration and start using advanced steganography features, please verify your email address:</p>
                
                <div style="text-align: center;">
                    <a href="{verification_url}" class="button">Verify Email Address</a>
                </div>
                
                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #667eea;">{verification_url}</p>
                
                <div class="warning">
                    <strong>⚠️ Security Note:</strong>
                    <ul>
                        <li>This link expires in 24 hours</li>
                        <li>If you didn't create an account, please ignore this email</li>
                        <li>Never share your password with anyone</li>
                    </ul>
                </div>
                
                <p>Once verified, you'll have access to:</p>
                <ul>
                    <li>🎭 Deniable Steganography</li>
                    <li>🚨 Duress Passwords</li>
                    <li>🔀 Shamir's Secret Sharing</li>
                    <li>🛡️ Post-Quantum Encryption</li>
                    <li>📜 Operation History</li>
                </ul>
            </div>
            
            <div class="footer">
                <p>This is an automated message from {APP_NAME}</p>
                <p>© {datetime.now().year} Advanced Steganography. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text_body = f"""
    Welcome to {APP_NAME}, {username}!
    
    Please verify your email address by clicking the link below:
    {verification_url}
    
    This link expires in 24 hours.
    
    If you didn't create an account, please ignore this email.
    """
    
    return send_email(to_email, subject, html_body, text_body)


def send_password_reset_email(to_email: str, username: str, reset_token: str):
    """Send password reset email"""
    reset_url = f"{APP_URL}?token={reset_token}&action=reset-password"
    
    subject = f"Reset your {APP_NAME} password"
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }}
            .container {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 30px;
                border-radius: 10px;
                color: white;
            }}
            .content {{
                background: white;
                color: #333;
                padding: 30px;
                border-radius: 8px;
                margin-top: 20px;
            }}
            .button {{
                display: inline-block;
                padding: 12px 30px;
                background: #f56565;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                margin: 20px 0;
                font-weight: bold;
            }}
            .footer {{
                margin-top: 30px;
                font-size: 12px;
                color: #666;
                text-align: center;
            }}
            .warning {{
                background: #fee;
                border-left: 4px solid #f56565;
                padding: 15px;
                margin: 20px 0;
                border-radius: 4px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 {APP_NAME}</h1>
            <div class="content">
                <h2>Password Reset Request</h2>
                <p>Hello {username},</p>
                <p>We received a request to reset your password. Click the button below to create a new password:</p>
                
                <div style="text-align: center;">
                    <a href="{reset_url}" class="button">Reset Password</a>
                </div>
                
                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #667eea;">{reset_url}</p>
                
                <div class="warning">
                    <strong>⚠️ Important Security Information:</strong>
                    <ul>
                        <li>This link expires in 1 hour</li>
                        <li>If you didn't request a password reset, please ignore this email</li>
                        <li>Your password won't change until you create a new one</li>
                        <li>Never share this link with anyone</li>
                    </ul>
                </div>
                
                <p><strong>Didn't request this?</strong> If you didn't ask to reset your password, someone may be trying to access your account. Please secure your account immediately.</p>
            </div>
            
            <div class="footer">
                <p>This is an automated message from {APP_NAME}</p>
                <p>© {datetime.now().year} Advanced Steganography. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text_body = f"""
    Password Reset Request - {APP_NAME}
    
    Hello {username},
    
    We received a request to reset your password. Click the link below to create a new password:
    {reset_url}
    
    This link expires in 1 hour.
    
    If you didn't request a password reset, please ignore this email.
    Your password won't change until you create a new one.
    """
    
    return send_email(to_email, subject, html_body, text_body)


def send_password_changed_notification(to_email: str, username: str):
    """Send notification that password was changed"""
    subject = f"Your {APP_NAME} password was changed"
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }}
            .container {{
                background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
                padding: 30px;
                border-radius: 10px;
                color: white;
            }}
            .content {{
                background: white;
                color: #333;
                padding: 30px;
                border-radius: 8px;
                margin-top: 20px;
            }}
            .footer {{
                margin-top: 30px;
                font-size: 12px;
                color: #666;
                text-align: center;
            }}
            .alert {{
                background: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 15px;
                margin: 20px 0;
                border-radius: 4px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 {APP_NAME}</h1>
            <div class="content">
                <h2>✅ Password Changed Successfully</h2>
                <p>Hello {username},</p>
                <p>This is a confirmation that your password was successfully changed on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}.</p>
                
                <div class="alert">
                    <strong>⚠️ Didn't make this change?</strong>
                    <p>If you didn't change your password, your account may be compromised. Please contact support immediately and secure your account.</p>
                </div>
                
                <p>For your security, we recommend:</p>
                <ul>
                    <li>Using a unique password for each online account</li>
                    <li>Enabling two-factor authentication when available</li>
                    <li>Never sharing your password with anyone</li>
                </ul>
            </div>
            
            <div class="footer">
                <p>This is an automated message from {APP_NAME}</p>
                <p>© {datetime.now().year} Advanced Steganography. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text_body = f"""
    Password Changed Successfully - {APP_NAME}
    
    Hello {username},
    
    This is a confirmation that your password was successfully changed on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}.
    
    If you didn't make this change, please contact support immediately.
    """
    
    return send_email(to_email, subject, html_body, text_body)