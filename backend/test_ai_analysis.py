
import asyncio
import os
import sys
import json

# Add backend to path
sys.path.append(os.getcwd())

from agents.base_agent import BaseSecurityAgent

# Mock agent
class MockAgent(BaseSecurityAgent):
    agent_name = "mock_agent"
    async def scan(self, *args, **kwargs):
        pass

async def test():
    print("🚀 Testing AI Analysis integration...")
    
    agent = MockAgent()
    
    # Mock finding representing a real SQL injection
    vuln_type = "SQL Injection"
    context = "Payload `' OR '1'='1` injected into `username` parameter"
    response = "Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/html/login.php on line 33"
    
    print(f"INPUT:\nType: {vuln_type}\nContext: {context}\nResponse: {response}\n")
    print("⏳ Calling analyze_with_ai (Groq)...")
    
    try:
        result = await agent.analyze_with_ai(vuln_type, context, response)
        print("\n✅ Analysis Result (JSON):")
        print(json.dumps(result, indent=2))
        
        # Verify structure
        if "is_vulnerable" in result and "confidence" in result:
             print("\n✅ Structure Verified: Valid JSON response from AI")
        else:
             print("\n❌ Invalid Structure: Missing key fields")
            
    except Exception as e:
        print(f"\n❌ Failed: {e}")
        import traceback
        traceback.print_exc()
    
    if hasattr(agent, 'close'):
        await agent.close()

if __name__ == "__main__":
    asyncio.run(test())
