
import requests
import json


# Register a fresh user to ensure login works
rand_id = __import__('random').randint(1000, 9999)
email = f"test{rand_id}@example.com"
password = "password123"

try:
    print(f"Registering user {email}...")
    reg_response = requests.post('http://localhost:8000/api/auth/register', json={
        "email": email,
        "username": f"user{rand_id}",
        "password": password,
        "full_name": "Test User"
    })
    
    # Login
    auth_response = requests.post('http://localhost:8000/api/auth/login', json={
        "email": email,
        "password": password
    })
    
    if auth_response.status_code == 200:
        token = auth_response.json()['access_token']
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test DAST Scan Creation (FULL)
        print("\n--- Testing scan_type: 'FULL' ---")
        response = requests.post(
            'http://localhost:8000/api/scans/', 
            json={
                "target_url": "http://testphp.vulnweb.com",
                "scan_type": "FULL",
                "agents_enabled": ["sql_injection", "xss"]
            },
            headers=headers
        )
        
        print(f"Status Code: {response.status_code}")
        if response.status_code != 200:
            print(f"Response: {response.text}")
        else:
            print(f"Success! Scan ID: {response.json().get('id')}")
    else:
        print(f"Login Failed: {auth_response.text}")

except Exception as e:
    print(f"Error: {e}")
