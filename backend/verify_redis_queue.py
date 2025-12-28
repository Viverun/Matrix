import os
import sys
from dotenv import load_dotenv
from redis import Redis
from rq import Queue

# Load env vars
load_dotenv()

# Add current dir to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import get_settings

def check_queue():
    print("=== Verifying Redis Queue ===")
    settings = get_settings()
    redis_url = getattr(settings, 'redis_url', 'redis://localhost:6379')
    print(f"Redis URL: {redis_url}")
    
    try:
        conn = Redis.from_url(redis_url)
        conn.ping()
        print("✅ Redis Connected")
        
        queue = Queue('scans', connection=conn)
        count = len(queue)
        print(f"Queue 'scans' length: {count}")
        
        if count > 0:
            print("Jobs in queue:")
            for job in queue.jobs:
                print(f" - {job.id} ({job.get_status()})")
        else:
            print("⚠️  Queue is empty")
            
        # Check failed queue
        failed_queue = Queue('failed', connection=conn)
        failed_count = len(failed_queue)
        print(f"Failed queue length: {failed_count}")
        if failed_count > 0:
             for job in failed_queue.jobs:
                print(f" - {job.id} (Error: {job.exc_info[:50]}...)")

    except Exception as e:
        print(f"❌ Redis Connection Failed: {e}")

if __name__ == "__main__":
    check_queue()
