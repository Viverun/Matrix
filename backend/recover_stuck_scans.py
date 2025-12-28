import asyncio
import os
import sys
from dotenv import load_dotenv
from sqlalchemy import select

# Load env vars
load_dotenv()

# Add current dir to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.database import async_session_maker
from models.scan import Scan, ScanStatus
from rq_tasks import enqueue_scan

async def recover_scans():
    print("=== Recovering Stuck Scans ===")
    
    async with async_session_maker() as db:
        # Find PENDING scans
        query = select(Scan).where(Scan.status == ScanStatus.PENDING)
        result = await db.execute(query)
        scans = result.scalars().all()
        
        print(f"Found {len(scans)} PENDING scans.")
        
        for scan in scans:
            print(f"Re-enqueuing Scan {scan.id} ({scan.scan_type})...")
            job_id = enqueue_scan(scan.id)
            if job_id:
                print(f"✅ Successfully enqueued: {job_id}")
            else:
                print(f"❌ Failed to enqueue Scan {scan.id}")

if __name__ == "__main__":
    asyncio.run(recover_scans())
