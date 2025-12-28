
import requests
import time
import sys
import json
import sqlite3

BASE_URL = "http://localhost:8000"
TARGET_URL = "http://testphp.vulnweb.com"

def run_test():
    print(f"🚀 Starting AI Analysis Verification for: {TARGET_URL}")
    
    # 1. Register/Login
    rand_id = int(time.time())
    email = f"ai_verifier_{rand_id}@example.com"
    password = "password123"
    
    try:
        # Register
        requests.post(f"{BASE_URL}/api/auth/register", json={
            "email": email,
            "username": f"ai_user_{rand_id}",
            "password": password,
            "full_name": "AI Verifier"
        })
        time.sleep(1)
        
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
        
        # 2. Create Scan (SQLi only for speed/certainty)
        print("📥 Creating Scan Job...")
        scan_payload = {
            "target_url": TARGET_URL,
            "scan_type": "FULL",
            "agents_enabled": ["sql_injection", "xss"]
        }
        
        create_resp = requests.post(
            f"{BASE_URL}/api/scans/", 
            json=scan_payload,
            headers=headers
        )
        
        if create_resp.status_code not in [200, 201]:
            print(f"❌ Scan Creation Failed: {create_resp.text}")
            return
            
        scan_id = create_resp.json()['id']
        print(f"✅ Scan ID: {scan_id} created. Waiting for results...")
        
        # 3. Poll Status
        start_time = time.time()
        timeout = 300 # 5 minutes
        
        while True:
            if time.time() - start_time > timeout:
                print("❌ Timeout")
                break
                
            status_resp = requests.get(f"{BASE_URL}/api/scans/{scan_id}", headers=headers)
            if status_resp.status_code != 200:
                time.sleep(2)
                continue
                
            data = status_resp.json()
            status = data['status']
            progress = data.get('progress', 0)
            
            print(f"   Status: {status} | Progress: {progress}%")
            
            if status in ['COMPLETED', 'FAILED', 'CANCELLED']:
                break
            
            # Use 'completed' (lowercase) or 'COMPLETED' (uppercase) check? API usually returns uppercase now
            if str(status).upper() == 'COMPLETED':
                break
                
            time.sleep(3)
            
        # 4. Check DB for AI Analysis
        print("\n🔎 Checking Database for AI Analysis...")
        conn = sqlite3.connect('matrix.db')
        cursor = conn.cursor()
        cursor.execute('SELECT title, ai_analysis FROM vulnerabilities WHERE scan_id=?', (scan_id,))
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            print("❌ No vulnerabilities found (Unexpected for testphp.vulnweb.com)")
        else:
            print(f"✅ Found {len(rows)} vulnerabilities.")
            for title, ai_analysis in rows:
                print(f"   - Title: {title}")
                print(f"   - AI Analysis Length: {len(str(ai_analysis))}")
                if len(str(ai_analysis)) > 50:
                    print(f"   - AI Analysis Snippet: {str(ai_analysis)[:100]}...")
                    if "is_vulnerable" in str(ai_analysis):
                        print("     ✅ AI Analysis contains JSON structure")
                    else:
                        print("     ⚠️ AI Analysis might not be JSON")
                else:
                    print("     ❌ AI Analysis is empty or too short")

    except Exception as e:
        print(f"❌ Exception: {e}")

if __name__ == "__main__":
    run_test()
