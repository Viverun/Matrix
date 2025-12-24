import httpx
import asyncio
import json

async def verify_refinements():
    base_url = "http://localhost:8000/api"
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Use Debug Token
        token = "debug-token"
        print("Using debug authentication bypass...")

        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Run Scan
        print("Starting benchmark scan...")
        scan_resp = await client.post(f"{base_url}/scans/", headers=headers, json={
            "target_url": "http://testphp.vulnweb.com",
            "target_name": "TestPHP Refinement Benchmark",
            "scan_type": "full",
            "agents_enabled": ["api_security", "xss"]
        })
        
        if scan_resp.status_code == 201:
            scan_id = scan_resp.json()["id"]
            print(f"Scan started successfully. ID: {scan_id}")
            
            # 3. Poll for results
            print("Waiting for results (max 2 mins)...")
            for _ in range(24):
                await asyncio.sleep(5)
                status_resp = await client.get(f"{base_url}/scans/{scan_id}", headers=headers)
                status_data = status_resp.json()
                print(f"Progress: {status_data['progress']}% | Status: {status_data['status']}")
                
                if status_data["status"] == "completed":
                    # 4. Analyze results
                    vulns_resp = await client.get(f"{base_url}/vulnerabilities/?scan_id={scan_id}", headers=headers)
                    vulns = vulns_resp.json().get("items", [])
                    print(f"\nScan Complete! Found {len(vulns)} vulnerabilities.")
                    
                    for v in vulns:
                        print(f"\n[-] {v['title']} ({v['severity']})")
                        print(f"    Impact: {v.get('impact')} | Likelihood: {v.get('likelihood')}")
                        print(f"    Rationale: {v.get('exploitability_rationale')}")
                        if v.get('cwe_id'): print(f"    CWE: {v['cwe_id']}")
                    break
                elif status_data["status"] == "failed":
                    print(f"Scan failed: {status_data.get('error_message')}")
                    break
        else:
            print(f"Scan execution failed ({scan_resp.status_code}): {scan_resp.text}")

if __name__ == "__main__":
    asyncio.run(verify_refinements())
