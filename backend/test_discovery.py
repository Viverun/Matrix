import asyncio
import sys
import os

# Add backend to path
sys.path.append(os.getcwd())

from scanner.target_analyzer import TargetAnalyzer

async def test_discovery():
    analyzer = TargetAnalyzer(timeout=30.0, max_depth=1)
    target = "http://testphp.vulnweb.com/"
    print(f"Analyzing {target}...")
    analysis = await analyzer.analyze(target)
    await analyzer.close()
    
    print(f"\nStatus: {analysis.status_code}")
    print(f"Server: {analysis.server}")
    print(f"Technologies: {analysis.technology_stack}")
    print(f"\nDiscovered {len(analysis.endpoints)} endpoints:")
    for ep in analysis.endpoints:
        print(f"- {ep.method} {ep.url} (Params: {ep.params})")

if __name__ == "__main__":
    asyncio.run(test_discovery())
