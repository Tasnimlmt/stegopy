
#!/usr/bin/env python3
"""
Email Diagnostic and Auto-Fix Tool
Identifies why emails aren't sending and helps fix it
"""

import os
import sys
from pathlib import Path

def print_header(text):
    print()
    print("=" * 70)
    print(text)
    print("=" * 70)
    print()

def check_env_file():
    """Check if .env file exists and is configured"""
    print_header("🔍 STEP 1: Checking .env Configuration")
    
    if not os.path.exists('.env'):
        print("❌ PROBLEM FOUND: .env file does NOT exist")
        print()
        print("This is why emails aren't sending - there's no email configuration!")
        print()
        return 'missing_env'
    
    print("✅ .env file exists")
    
    # Read and check content
    with open('.env', 'r') as f:
        content = f.read()
    
    # Check for default/unconfigured values
    if 'your-email@gmail.com' in content:
        print("❌ PROBLEM FOUND: .env has default values (not configured)")
        print()
        print("The file exists but you haven't added your real email settings!")
        print()
        return 'unconfigured_env'
    
    if 'your-app-password' in content:
        print("❌ PROBLEM FOUND: .env still has placeholder password")
        print()
        return 'unconfigured_env'
    
    # Check if required variables exist
    required_vars = ['SMTP_SERVER', 'SMTP_USERNAME', 'SMTP_PASSWORD']
    missing = []
    
    for var in required_vars:
        if var not in content:
            missing.append(var)
    
    if missing:
        print(f"❌ PROBLEM FOUND: Missing variables: {', '.join(missing)}")
        print()
        return 'incomplete_env'
    
    print("✅ .env appears to be configured")
    return 'ok'

def check_dotenv_installed():
    """Check if python-dotenv is installed"""
    print_header("🔍 STEP 2: Checking python-dotenv Module")
    
    try:
        import dotenv
        print("✅ python-dotenv is installed")
        return True
    except ImportError:
        print("❌ PROBLEM FOUND: python-dotenv NOT installed")
        print()
        print("Without this, the app can't read your .env file!")
        print()
        return False

def check_email_utils_imports_dotenv():
    """Check if email_utils.py loads dotenv"""
    print_header("🔍 STEP 3: Checking email_utils.py Configuration")
    
    if not os.path.exists('email_utils.py'):
        print("❌ PROBLEM FOUND: email_utils.py not found")
        print()
        print("Make sure you're running this from the backend directory")
        print()
        return False
    
    with open('email_utils.py', 'r') as f:
        content = f.read()
    
    if 'load_dotenv' not in content:
        print("❌ PROBLEM FOUND: email_utils.py doesn't load .env file")
        print()
        print("The file needs to import and call load_dotenv()")
        print()
        return False
    
    if 'from dotenv import load_dotenv' not in content:
        print("⚠️  WARNING: load_dotenv import might be missing")
        return False
    
    print("✅ email_utils.py is configured to load .env")
    return True

def show_current_config():
    """Show current email configuration (masked)"""
    print_header("📋 Current Email Configuration")
    
    try:
        from dotenv import load_dotenv
        load_dotenv()
        
        config = {
            'SMTP_SERVER': os.getenv('SMTP_SERVER', 'NOT SET'),
            'SMTP_PORT': os.getenv('SMTP_PORT', 'NOT SET'),
            'SMTP_USERNAME': os.getenv('SMTP_USERNAME', 'NOT SET'),
            'SMTP_PASSWORD': os.getenv('SMTP_PASSWORD', 'NOT SET'),
            'FROM_EMAIL': os.getenv('FROM_EMAIL', 'NOT SET'),
        }
        
        print("Current values in .env:")
        print("-" * 70)
        for key, value in config.items():
            if 'PASSWORD' in key and value != 'NOT SET':
                display = '*' * min(len(value), 20)
            else:
                display = value
            
            status = "❌" if value == 'NOT SET' else "✅"
            print(f"{status} {key:20} = {display}")
        
        print("-" * 70)
        print()
        
        # Check for problems
        problems = [k for k, v in config.items() if v == 'NOT SET']
        if problems:
            print(f"❌ These variables are NOT SET: {', '.join(problems)}")
            return False
        
        # Check for default values
        if 'your-email@gmail.com' in config['SMTP_USERNAME']:
            print("❌ SMTP_USERNAME still has default value!")
            return False
        
        if 'your-app-password' in config['SMTP_PASSWORD']:
            print("❌ SMTP_PASSWORD still has default value!")
            return False
        
        print("✅ All variables are set")
        return True
        
    except Exception as e:
        print(f"❌ Error reading configuration: {e}")
        return False

def test_smtp_connection():
    """Test actual SMTP connection"""
    print_header("🔍 STEP 4: Testing SMTP Connection")
    
    try:
        from dotenv import load_dotenv
        import smtplib
        
        load_dotenv()
        
        SMTP_SERVER = os.getenv('SMTP_SERVER')
        SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
        SMTP_USERNAME = os.getenv('SMTP_USERNAME')
        SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
        
        print(f"Attempting to connect to {SMTP_SERVER}:{SMTP_PORT}...")
        print(f"Using username: {SMTP_USERNAME}")
        print()
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            print("✅ Connected to SMTP server")
            
            server.starttls()
            print("✅ TLS encryption started")
            
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            print("✅ Authentication successful")
        
        print()
        print("🎉 SMTP CONNECTION TEST PASSED!")
        print()
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ AUTHENTICATION FAILED: {e}")
        print()
        print("PROBLEM: Your username or password is wrong")
        print()
        print("For Gmail users:")
        print("  • You MUST use an App Password, not your regular password")
        print("  • Generate one at: https://myaccount.google.com/apppasswords")
        print("  • Make sure 2-Factor Authentication is enabled first")
        print()
        return False
        
    except Exception as e:
        print(f"❌ CONNECTION FAILED: {e}")
        print()
        return False

def offer_solutions(problem_type):
    """Offer solutions based on problem type"""
    print_header("💡 RECOMMENDED SOLUTION")
    
    if problem_type == 'missing_env':
        print("SOLUTION: Create and configure .env file")
        print()
        print("Run the interactive setup wizard:")
        print("   python setup_email.py")
        print()
        print("This will guide you through setting up Gmail, Outlook, or other email providers.")
        print()
        
    elif problem_type == 'unconfigured_env':
        print("SOLUTION: Configure your .env file with real values")
        print()
        print("Option 1: Run the setup wizard (EASIEST)")
        print("   python setup_email.py")
        print()
        print("Option 2: Edit .env manually")
        print("   1. Open .env in a text editor")
        print("   2. Replace the placeholder values:")
        print("      SMTP_USERNAME=your-real-email@gmail.com")
        print("      SMTP_PASSWORD=your-real-app-password")
        print()
        
    elif problem_type == 'no_dotenv':
        print("SOLUTION: Install python-dotenv")
        print()
        print("Run this command:")
        print("   pip install python-dotenv")
        print()
        print("Then re-run this diagnostic to continue.")
        print()
        
    elif problem_type == 'auth_failed':
        print("SOLUTION: Fix authentication credentials")
        print()
        print("For GMAIL users:")
        print("   1. Go to: https://myaccount.google.com/apppasswords")
        print("   2. Enable 2-Factor Authentication if not already enabled")
        print("   3. Create a new App Password for 'Mail'")
        print("   4. Copy the 16-character password")
        print("   5. Put it in .env as SMTP_PASSWORD")
        print()
        print("For OTHER providers:")
        print("   • Check that SMTP_USERNAME is your full email address")
        print("   • Check that SMTP_PASSWORD is correct")
        print("   • Some providers also require app-specific passwords")
        print()

def quick_fix_menu():
    """Show quick fix menu"""
    print_header("🔧 QUICK FIX OPTIONS")
    
    print("Choose an option:")
    print()
    print("1. Run interactive email setup (RECOMMENDED)")
    print("2. Install missing dependencies")
    print("3. Test current configuration")
    print("4. Show Gmail setup instructions")
    print("5. Exit")
    print()
    
    choice = input("Enter choice (1-5): ").strip()
    
    if choice == '1':
        print()
        print("Starting interactive setup...")
        print()
        os.system(f"{sys.executable} setup_email.py")
        
    elif choice == '2':
        print()
        print("Installing dependencies...")
        os.system(f"{sys.executable} -m pip install python-dotenv")
        print()
        print("✅ Dependencies installed!")
        
    elif choice == '3':
        print()
        test_smtp_connection()
        
    elif choice == '4':
        show_gmail_instructions()
        
    elif choice == '5':
        print("Exiting...")
        return

def show_gmail_instructions():
    """Show detailed Gmail setup instructions"""
    print_header("📧 GMAIL SETUP INSTRUCTIONS")
    
    print("STEP 1: Enable 2-Factor Authentication")
    print("-" * 70)
    print("1. Go to: https://myaccount.google.com/security")
    print("2. Find '2-Step Verification'")
    print("3. Click 'Get Started'")
    print("4. Follow the instructions to enable 2FA")
    print()
    
    print("STEP 2: Generate App Password")
    print("-" * 70)
    print("1. Go to: https://myaccount.google.com/apppasswords")
    print("2. You may need to log in again")
    print("3. Under 'Select app', choose 'Mail'")
    print("4. Under 'Select device', choose 'Other' and name it 'Steganography App'")
    print("5. Click 'Generate'")
    print("6. Copy the 16-character password (it looks like: abcd efgh ijkl mnop)")
    print("   IMPORTANT: Copy it WITHOUT spaces!")
    print()
    
    print("STEP 3: Update .env file")
    print("-" * 70)
    print("1. Open .env in a text editor")
    print("2. Set these values:")
    print()
    print("   SMTP_SERVER=smtp.gmail.com")
    print("   SMTP_PORT=587")
    print("   SMTP_USERNAME=your-actual-email@gmail.com")
    print("   SMTP_PASSWORD=abcdefghijklmnop  (paste your app password here)")
    print("   FROM_EMAIL=your-actual-email@gmail.com")
    print()
    print("3. Save the file")
    print("4. Run this diagnostic again to test")
    print()

def main():
    """Main diagnostic routine"""
    print()
    print("=" * 70)
    print("📧 EMAIL DIAGNOSTIC TOOL")
    print("   Finding out why emails aren't sending...")
    print("=" * 70)
    
    problems = []
    
    # Check 1: .env file
    env_status = check_env_file()
    if env_status != 'ok':
        problems.append(env_status)
    
    # Check 2: python-dotenv
    if not check_dotenv_installed():
        problems.append('no_dotenv')
        print()
        print("⚠️  Cannot continue without python-dotenv")
        offer_solutions('no_dotenv')
        print()
        choice = input("Install it now? (y/n): ").lower()
        if choice == 'y':
            os.system(f"{sys.executable} -m pip install python-dotenv")
            print()
            print("Please run this diagnostic again after installation.")
        return
    
    # Check 3: email_utils.py configuration
    if not check_email_utils_imports_dotenv():
        problems.append('email_utils_not_configured')
    
    # Check 4: Show current config
    config_ok = show_current_config()
    if not config_ok:
        problems.append('config_invalid')
    
    # If basic checks failed, offer solutions
    if problems:
        print()
        print("=" * 70)
        print("❌ PROBLEMS DETECTED")
        print("=" * 70)
        print()
        print("Email is NOT configured properly. That's why emails aren't sending!")
        print()
        
        # Offer most relevant solution
        if 'missing_env' in problems or 'unconfigured_env' in problems:
            offer_solutions(problems[0])
        
        quick_fix_menu()
        return
    
    # If config looks good, test SMTP connection
    if test_smtp_connection():
        print()
        print("=" * 70)
        print("✅ EMAIL IS CONFIGURED CORRECTLY!")
        print("=" * 70)
        print()
        print("Your email configuration is working!")
        print()
        print("If you're still not receiving emails:")
        print("  1. Check your spam/junk folder")
        print("  2. Make sure you restarted your Flask app after configuring email")
        print("  3. Check backend logs for any error messages")
        print("  4. Try sending a test email:")
        print("     python send_test_email.py")
        print()
    else:
        offer_solutions('auth_failed')
        print()
        input("Press Enter to see quick fix menu...")
        quick_fix_menu()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDiagnostic cancelled")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
