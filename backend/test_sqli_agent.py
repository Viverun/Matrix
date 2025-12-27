import asyncio
import sys
import os
from typing import List, Dict, Any

# Add backend to path
sys.path.append(os.getcwd())

from agents.sql_injection_agent import SQLInjectionAgent
from models.scan import Scan

async def test_sqli_agent():
    print("Initializing SQLInjectionAgent...")
    agent = SQLInjectionAgent()
    
    # Target info
    target_url = "http://testphp.vulnweb.com"
    endpoint = {
        "url": "http://testphp.vulnweb.com/listproducts.php",
        "method": "GET",
        "params": {"cat": "1"}
    }
    
    print(f"Testing {endpoint['url']} with params {endpoint['params']}...")
    
    # Run scan
    results = await agent.scan(
        target_url=target_url,
        endpoints=[endpoint],
        technology_stack=["PHP", "MySQL", "Nginx"]
    )
    
    print(f"\nScan complete. Found {len(results)} vulnerabilities.")
    for res in results:
        print(f"\n[VULNERABILITY] {res.title}")
        print(f"Severity: {res.severity}")
        print(f"Evidence: {res.evidence}")
        print(f"Description: {res.description}")

if __name__ == "__main__":
    asyncio.run(test_sqli_agent())
