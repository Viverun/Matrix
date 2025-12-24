import httpx
import json

def start_scan():
    url = "http://localhost:8000/api/scans/"
    headers = {
        "Authorization": "Bearer debug-token",
        "Content-Type": "application/json"
    }
    data = {
        "target_url": "http://testphp.vulnweb.com",
        "agents_enabled": ["xss", "sql_injection", "api_security", "authentication"]
    }
    
    try:
        response = httpx.post(url, headers=headers, json=data, timeout=30)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    start_scan()
