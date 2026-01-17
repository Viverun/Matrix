
import asyncio
import sys
import os
import logging

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

from agents.sql_injection_agent import SQLInjectionAgent, SQLInjectionConfig
from models.vulnerability import VulnerabilityType

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Override login endpoints to only test the one we care about
SQLInjectionConfig.LOGIN_ENDPOINTS = ["/api/user/login"]

async def run_test():
    print("[-] Starting SQL Injection Reproduction Test against rest.vulnweb.com")
    
    agent = SQLInjectionAgent()
    
    # Target: Known vulnerable login endpoint
    target_url = "http://rest.vulnweb.com/"
    
    # We manually construct the endpoint that the scanner SHOULD have found
    endpoints = [
        {
            "url": "http://rest.vulnweb.com/api/user/login",
            "method": "POST",
            "params": {"email": "test@test.com", "password": "password"}, # JSON body usually
            "api_type": "json" 
        }
    ]
    
    print(f"[-] Testing {len(endpoints)} endpoint(s)...")
    
    try:
        results = await agent.scan(target_url, endpoints)
        
        print(f"[-] Scan complete. Found {len(results)} vulnerabilities.")
        
        found_sqli = False
        for res in results:
            print(f"[!] Found: {res.title} ({res.severity.value}) at {res.url}")
            if res.vulnerability_type == VulnerabilityType.SQL_INJECTION:
                found_sqli = True
                
        if found_sqli:
            print("[+] SUCCESS: SQL Injection detected!")
        else:
            print("[-] FAILURE: SQL Injection NOT detected.")
            
    except Exception as e:
        print(f"[-] ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await agent.close()

if __name__ == "__main__":
    asyncio.run(run_test())
