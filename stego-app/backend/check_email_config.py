#!/usr/bin/env python3
"""
Email Configuration Checker and Test Utility
Run this script to diagnose email issues
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def check_env_file():
    """Check if .env file exists and has required variables"""
    print("=" * 70)
    print("📧 EMAIL CONFIGURATION CHECKER")
    print("=" * 70)
    print()
    
    # Check if .env exists
    if os.path.exists('.env'):
        print("✅ .env file found")
    else:
        print("❌ .env file NOT found!")
        print()
        print("📝 To fix this:")
        print("   1. Copy .env.example to .env")
        print("   2. Edit .env with your email settings")
        print()
        print("   Command: cp .env.example .env")
        print()
        return False
    
    # Check required variables
    required_vars = {
        'SMTP_SERVER': 'SMTP server address (e.g., smtp.gmail.com)',
        'SMTP_PORT': 'SMTP port (usually 587)',
        'SMTP_USERNAME': 'Your email address',
        'SMTP_PASSWORD': 'Your email password or app password',
        'FROM_EMAIL': 'Sender email address',
        'APP_URL': 'Your application URL'
    }
    
    print()
    print("Checking environment variables...")
    print("-" * 70)
    
    all_configured = True
    for var, description in required_vars.items():
        value = os.getenv(var)
        if not value or value in ['your-email@gmail.com', 'your-app-password', 'your-16-char-app-password']:
            print(f"❌ {var}: NOT CONFIGURED")
            print(f"   ({description})")
            all_configured = False
        else:
            # Mask password for security
            if 'PASSWORD' in var:
                display_value = '*' * len(value)
            else:
                display_value = value
            print(f"✅ {var}: {display_value}")
    
    print("-" * 70)
    return all_configured


def test_smtp_connection():
    """Test SMTP connection"""
    print()
    print("Testing SMTP connection...")
    print("-" * 70)
    
    try:
        import smtplib
        
        SMTP_SERVER = os.getenv('SMTP_SERVER')
        SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
        SMTP_USERNAME = os.getenv('SMTP_USERNAME')
        SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
        
        print(f"Connecting to {SMTP_SERVER}:{SMTP_PORT}...")
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            print("✅ Connected successfully")
            
            print("Starting TLS encryption...")
            server.starttls()
            print("✅ TLS started")
            
            print(f"Authenticating with {SMTP_USERNAME}...")
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            print("✅ Authentication successful")
        
        print("-" * 70)
        print("🎉 SMTP connection test PASSED!")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ Authentication FAILED: {e}")
        print()
        print("💡 Common fixes:")
        print("   • For Gmail: Use an 'App Password', not your regular password")
        print("   • Generate App Password: https://myaccount.google.com/apppasswords")
        print("   • Make sure 2-Factor Authentication is enabled on your account")
        return False
        
    except ConnectionRefusedError as e:
        print(f"❌ Connection REFUSED: {e}")
        print()
        print("💡 Common fixes:")
        print("   • Check SMTP_SERVER and SMTP_PORT are correct")
        print("   • Make sure your firewall allows connections")
        print("   • Verify your internet connection")
        return False
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def send_test_email():
    """Send a test email"""
    print()
    print("Sending test email...")
    print("-" * 70)
    
    to_email = input("Enter email address to send test to (or press Enter to skip): ").strip()
    
    if not to_email:
        print("Skipped test email")
        return
    
    try:
        from email_utils import send_verification_email
        
        print(f"Sending verification email to {to_email}...")
        success = send_verification_email(to_email, "TestUser", "test-token-123456")
        
        if success:
            print("✅ Test email sent successfully!")
            print(f"   Check inbox for {to_email}")
        else:
            print("❌ Failed to send test email")
            print("   Check the error messages above")
            
    except ImportError as e:
        print(f"❌ Cannot import email_utils: {e}")
        print("   Make sure email_utils.py is in the same directory")
    except Exception as e:
        print(f"❌ Error: {e}")


def show_gmail_setup():
    """Show Gmail setup instructions"""
    print()
    print("=" * 70)
    print("📧 GMAIL SETUP INSTRUCTIONS")
    print("=" * 70)
    print()
    print("Step 1: Enable 2-Factor Authentication")
    print("   • Go to: https://myaccount.google.com/security")
    print("   • Find '2-Step Verification'")
    print("   • Click 'Get Started' and follow the instructions")
    print()
    print("Step 2: Generate App Password")
    print("   • Go to: https://myaccount.google.com/apppasswords")
    print("   • Select 'Mail' and your device")
    print("   • Click 'Generate'")
    print("   • Copy the 16-character password")
    print()
    print("Step 3: Update .env file")
    print("   SMTP_SERVER=smtp.gmail.com")
    print("   SMTP_PORT=587")
    print("   SMTP_USERNAME=your-email@gmail.com")
    print("   SMTP_PASSWORD=your-16-char-app-password  # Paste the generated password here")
    print("   FROM_EMAIL=your-email@gmail.com")
    print("   APP_URL=http://localhost:5000")
    print()
    print("=" * 70)


def show_alternative_providers():
    """Show configuration for alternative email providers"""
    print()
    print("=" * 70)
    print("📧 ALTERNATIVE EMAIL PROVIDERS")
    print("=" * 70)
    print()
    
    print("Option 1: OUTLOOK/HOTMAIL")
    print("-" * 40)
    print("SMTP_SERVER=smtp-mail.outlook.com")
    print("SMTP_PORT=587")
    print("SMTP_USERNAME=your-email@outlook.com")
    print("SMTP_PASSWORD=your-password")
    print()
    
    print("Option 2: YAHOO")
    print("-" * 40)
    print("SMTP_SERVER=smtp.mail.yahoo.com")
    print("SMTP_PORT=587")
    print("SMTP_USERNAME=your-email@yahoo.com")
    print("SMTP_PASSWORD=your-app-password")
    print("Note: Yahoo also requires app-specific password")
    print()
    
    print("Option 3: SENDGRID (Recommended for Production)")
    print("-" * 40)
    print("1. Sign up at https://sendgrid.com (100 emails/day free)")
    print("2. Create an API key")
    print("3. Configure:")
    print("   SMTP_SERVER=smtp.sendgrid.net")
    print("   SMTP_PORT=587")
    print("   SMTP_USERNAME=apikey")
    print("   SMTP_PASSWORD=your-sendgrid-api-key")
    print()
    print("=" * 70)


def main():
    """Main function"""
    print()
    
    # Check .env configuration
    config_ok = check_env_file()
    
    if not config_ok:
        print()
        print("⚠️  Email is NOT configured properly!")
        print()
        choice = input("Would you like to see Gmail setup instructions? (y/n): ").lower()
        if choice == 'y':
            show_gmail_setup()
        
        choice = input("Would you like to see alternative providers? (y/n): ").lower()
        if choice == 'y':
            show_alternative_providers()
        
        print()
        print("After configuring .env, run this script again to test.")
        return
    
    print()
    print("✅ All environment variables are configured!")
    print()
    
    # Test SMTP connection
    connection_ok = test_smtp_connection()
    
    if not connection_ok:
        print()
        print("⚠️  SMTP connection test FAILED!")
        print()
        choice = input("Would you like to see Gmail setup instructions? (y/n): ").lower()
        if choice == 'y':
            show_gmail_setup()
        return
    
    # Send test email
    print()
    print("✅ SMTP connection test PASSED!")
    send_test_email()
    
    print()
    print("=" * 70)
    print("✅ Email configuration check complete!")
    print("=" * 70)
    print()
    print("If everything passed, your email system is ready to use!")
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest cancelled by user")
        sys.exit(0)
