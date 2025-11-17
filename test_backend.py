
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
        return False
    print()

if __name__ == "__main__":
    print("🚀 Starting Backend Tests...\n")
    
    # Test if backend is responding
    if test_health():
        print("✅ Backend is working correctly!")
        print("\nYou can now proceed to build the full application.")
    else:
        print("❌ Backend is not responding. Check if server is running.")