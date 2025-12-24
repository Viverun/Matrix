import asyncio
import httpx
import time
import sys
import traceback
import json

BASE_URL = "http://127.0.0.1:8000/api"

async def main():
    async with httpx.AsyncClient(timeout=60.0) as client:
        # 1. Register/Login
        print("[INFO] Authenticating...")
        email = "tester@test.com"
        password = "testpassword123"
        username = "tester"
        
        try:
            resp = await client.post(f"{BASE_URL}/auth/register", json={
                "email": email,
                "password": password,
                "username": username,
                "full_name": "Test User",
                "company": "Test Corp"
            })
            if resp.status_code == 201:
                token = resp.json()["access_token"]
                print("[INFO] Registered and logged in.")
            else:
                resp = await client.post(f"{BASE_URL}/auth/login", json={
                    "email": email,
                    "password": password
                })
                if resp.status_code == 200:
                    token = resp.json()["access_token"]
                    print("[INFO] Logged in.")
                else:
                    print(f"[ERROR] Auth failed: {resp.text}")
                    return
        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
            traceback.print_exc()
            return

        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Trigger Scan against Test Bench
        print("\n[INFO] Triggering Scan against LOCAL TEST BENCH...")
        # Pointing to the internal test bench
        target_url = "http://localhost:8000/api/test" 
        
        resp = await client.post(f"{BASE_URL}/scans/", json={
            "target_url": target_url,
            "target_name": "Test Bench Scan",
            "scan_type": "full",
            "agents_enabled": ["sql_injection", "xss"] 
        }, headers=headers)
        
        if resp.status_code != 201:
            print(f"[ERROR] Failed to create scan: {resp.text}")
            return
            
        scan_id = resp.json()["id"]
        print(f"[INFO] Scan created with ID: {scan_id}")
        
        # Poll for completion
        status = "pending"
        while status not in ["completed", "failed", "cancelled"]:
            await asyncio.sleep(2)
            resp = await client.get(f"{BASE_URL}/scans/{scan_id}", headers=headers)
            scan_data = resp.json()
            status = scan_data["status"]
            print(f"[INFO] Scan Status: {status} (Progress: {scan_data.get('progress', 0)}%)")
        
        if status != "completed":
            print(f"[ERROR] Scan failed: {scan_data.get('error_message', 'No error details')}")
            return

        # 3. Verify Findings
        print("\n[INFO] Verifying Findings...")
        # We need to fetch vulnerabilities
        # Ideally there is an endpoint for this, but let's assume we can get it from scan details if expanded,
        # or we might need to hit a vulnerabilities endpoint.
        # Checking if 'vulnerabilities' is in scan_data response or we need to query /api/vulnerabilities?scan_id=...
        
        # Let's try querying vulnerabilities endpoint
        resp = await client.get(f"{BASE_URL}/vulnerabilities/?scan_id={scan_id}", headers=headers)
        vulns = resp.json().get("items", [])
        
        print(f"[INFO] Found {len(vulns)} vulnerabilities.")
        
        found_xss = False
        found_sqli = False
        
        for v in vulns:
            # The API returns 'vulnerability_type', checking both just in case
            v_type = v.get('vulnerability_type', v.get('type', 'unknown'))
            print(f" - [{v['severity']}] {v['title']} ({v_type})")
            if "xss" in v_type.lower():
                found_xss = True
            if "sql" in v_type.lower():
                found_sqli = True
        
        if found_xss and found_sqli:
            print("\n[SUCCESS] Agents successfully detected XSS and SQLi in the test bench!")
        else:
            print("\n[WARNING] Some expected vulnerabilities were NOT found.")
            if not found_xss: print(" - Missed XSS")
            if not found_sqli: print(" - Missed SQLi")

if __name__ == "__main__":
    asyncio.run(main())
