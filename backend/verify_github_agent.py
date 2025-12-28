
import asyncio
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.agents.github_agent import GithubSecurityAgent
from backend.core.hugging_face_client import hf_client_ii

async def verify_agent():
    print("Verifying GithubSecurityAgent fix...")
    
    agent = GithubSecurityAgent()
    
    test_content = """
    def dangerous_query(user_input):
        # Vulnerable to SQLi
        return db.execute("SELECT * FROM users WHERE name = " + user_input)
    """
    
    print("\nCalling _ai_analysis...")
    try:
        results = await agent._ai_analysis(
            content=test_content,
            file_path="vuln.py",
            owner="test",
            repo="test",
            branch="main"
        )
        
        print(f"Results found: {len(results)}")
        for res in results:
            print(f"- Type: {res.vulnerability_type}")
            print(f"  Title: {res.title}")
            print(f"  AI Analysis: {res.ai_analysis[:100]}...")
            
    except Exception as e:
        print(f"Error during agent execution: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(verify_agent())
