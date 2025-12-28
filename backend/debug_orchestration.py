
import asyncio
import logging
import sys
from agents.orchestrator import AgentOrchestrator

# Configure logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | [%(name)s] %(message)s',
    stream=sys.stdout
)

async def main():
    target = "http://testphp.vulnweb.com"
    orchestrator = AgentOrchestrator()
    
    print(f"🚀 Starting direct scan of {target}")
    try:
        results = await orchestrator.run_scan(
            target_url=target,
            agents_enabled=["sql_injection", "xss"]
        )
        
        print(f"\n✅ Scan Finished. Results: {len(results)}")
        for r in results:
            print(f"   - {r.title} ({r.severity})")
            
    except Exception as e:
        print(f"❌ Scan Failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
