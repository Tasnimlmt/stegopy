#!/usr/bin/env python3
"""
Simple test script for the backend - No external dependencies needed
"""

import http.client
import json

def test_backend_simple():
    print("🚀 Testing Backend Connection...")
    print("=" * 40)
    
    try:
        # Test health endpoint
        connection = http.client.HTTPConnection("localhost", 5000)
        connection.request("GET", "/api/health")
        response = connection.getresponse()
        
        print(f"Status: {response.status}")
        print(f"Reason: {response.reason}")
        
        data = response.read().decode()
        print(f"Response: {data}")
        
        if response.status == 200:
            print("✅ Backend is working correctly!")
        else:
            print("❌ Backend returned an error")
            
        connection.close()
        
    except ConnectionRefusedError:
        print("❌ Cannot connect to backend. Make sure it's running on localhost:5000")
        print("   Run: python app.py")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_database():
    print("\n" + "=" * 40)
    print("Testing Database Connection...")
    
    try:
        connection = http.client.HTTPConnection("localhost", 5000)
        connection.request("GET", "/api/test-db")
        response = connection.getresponse()
        
        print(f"Status: {response.status}")
        data = response.read().decode()
        print(f"Response: {data}")
        
        if response.status == 200:
            print("✅ Database endpoint is working!")
        else:
            print("❌ Database endpoint returned an error")
            
        connection.close()
        
    except Exception as e:
        print(f"❌ Error testing database: {e}")

if __name__ == "__main__":
    test_backend_simple()
    test_database()
    print("\n📝 Next: Add user registration and login endpoints")