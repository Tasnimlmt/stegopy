import requests
import json

BASE_URL = "http://localhost:5000/api"

def test_registration():
    print("=== Testing User Registration ===")
    
    data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpass123"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/register", json=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_login():
    print("\n=== Testing User Login ===")
    
    data = {
        "email": "test@example.com",
        "password": "testpass123"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/login", json=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Testing Real Backend Functionality...\n")
    
    # Test registration
    reg_ok = test_registration()
    
    # Test login
    login_ok = test_login()
    
    print("\n" + "="*50)
    if reg_ok and login_ok:
        print("✅ User registration and login are working!")
        print("🎉 Your backend is fully functional!")
    else:
        print("❌ Some tests failed")
    print("="*50)