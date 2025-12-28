
import requests
import time
import sys
import json

BASE_URL = "http://localhost:8000"
TARGET_URL = "https://consult-ai-inky.vercel.app/"

def run_test():
    print(f"🚀 Starting Verification Scan for: {TARGET_URL}")
    
    # 1. Register/Login
    rand_id = int(time.time())
    email = f"verifier_{rand_id}@example.com"
    password = "password123"
    
    try:
        # Register (ignore if exists)
        reg_response = requests.post(f"{BASE_URL}/api/auth/register", json={
            "email": email,
            "username": f"verifier_{rand_id}",
            "password": password,
            "full_name": "Verifier"
        })
        print(f"📝 Registration Status: {reg_response.status_code}")
        if reg_response.status_code not in [200, 201]:
             print(f"⚠️ Registration Info: {reg_response.text}")

        time.sleep(1) # Allow DB to sync
        
        # Login
        print("🔑 Authenticating...")
        auth_resp = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": email,
            "password": password
        })
        
        if auth_resp.status_code != 200:
            print(f"❌ Login failed: {auth_resp.text}")
            return
            
        token = auth_resp.json()['access_token']
        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Create Scan
        print("📥 Creating Scan Job...")
        scan_payload = {
            "target_url": TARGET_URL,
            "scan_type": "FULL",
            "agents_enabled": ["sql_injection", "xss", "api_security"]
        }
        
        create_resp = requests.post(
            f"{BASE_URL}/api/scans/", 
            json=scan_payload,
            headers=headers
        )
        
        if create_resp.status_code != 200:
            print(f"❌ Scan Creation Failed: {create_resp.text}")
            return
            
        scan_id = create_resp.json()['id']
        print(f"✅ Scan ID: {scan_id} created. Status: {create_resp.json()['status']}")
        
        # 3. Poll Status
        print("⏳ Polling for results...")
        start_time = time.time()
        timeout = 300 # 5 minutes timeout
        
        while True:
            if time.time() - start_time > timeout:
                print("❌ Timeout waiting for scan completion")
                break
                
            status_resp = requests.get(f"{BASE_URL}/api/scans/{scan_id}", headers=headers)
            if status_resp.status_code != 200:
                print(f"⚠️ Error checking status: {status_resp.status_code}")
                time.sleep(2)
                continue
                
            data = status_resp.json()
            status = data['status']
            progress = data.get('progress', 0)
            
            print(f"   Status: {status.upper()} | Progress: {progress}%")
            
            if status in ['completed', 'failed', 'cancelled']:
                print(f"\n🏁 Scan Finished with status: {status}")
                
                if status == 'completed':
                    # Get Vulnerabilities
                    vuln_resp = requests.get(f"{BASE_URL}/api/scans/{scan_id}/vulnerabilities", headers=headers)
                    vulns = vuln_resp.json()['items']
                    print(f"\n🔎 Vulnerabilities Found: {len(vulns)}")
                    for v in vulns:
                        print(f"   - [{v['severity'].upper()}] {v['title']}")
                else:
                     print(f"❌ Error Message: {data.get('error_message')}")
                break
                
            time.sleep(3)
            
    except Exception as e:
        print(f"❌ Exception: {e}")

if __name__ == "__main__":
    run_test()
