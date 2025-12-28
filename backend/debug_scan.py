import asyncio
import logging
import traceback
import sys
import os
from dotenv import load_dotenv

# Load env vars
load_dotenv()

# Add current dir to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from rq_tasks import _execute_scan_async

async def debug_scan():
    print("=== Debugging Scan 22 ===")
    try:
        result = await _execute_scan_async(22)
        print("✅ Scan Completed Successfully")
        print(result)
    except Exception as e:
        print(f"❌ Scan Failed: {e}")
        traceback.print_exc()
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(debug_scan())
