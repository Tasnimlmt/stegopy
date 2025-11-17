import requests
import json
import time

BASE_URL = "http://localhost:5000/api"

def test_health():
    print("=== Testing Health Check ===")
    try:
        response = requests.get(f"{BASE_URL}/health")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure the server is running with: python3 app_very_simple.py")
        return False

def test_registration():
    print("\n=== Testing User Registration ===")
    
    # Use unique username/email to avoid duplicates
    timestamp = int(time.time())
    
    data = {
        "username": f"testuser{timestamp}",
        "email": f"test{timestamp}@example.com",
        "password": "testpass123"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/register", json=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return data  # Return the test data for login
    except Exception as e:
        print(f"Error: {e}")
        return None

def test_login(user_data):
    if not user_data:
        return False
        
    print("\n=== Testing User Login ===")
    
    data = {
        "email": user_data["email"],
        "password": user_data["password"]
    }
    
    try:
        response = requests.post(f"{BASE_URL}/login", json=data)
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Testing Backend Registration & Login...\n")
    
    # Test health first
    health_ok = test_health()
    
    if health_ok:
        # Test registration and login
        user_data = test_registration()
        if user_data:
            login_ok = test_login(user_data)
            
            print("\n" + "="*50)
            if login_ok:
                print("✅ SUCCESS! Backend is fully working!")
                print("🎉 You can now build the frontend!")
            else:
                print("❌ Login failed")
        else:
            print("❌ Registration failed")
    else:
        print("❌ Server is not running")
    
    print("="*50)
