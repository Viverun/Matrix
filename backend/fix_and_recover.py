import asyncio
import os
import sys
import sqlite3
from dotenv import load_dotenv

# Load env vars
load_dotenv()

# Add current dir to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from rq_tasks import enqueue_scan

def fix_and_recover():
    print("=== Fixing Data & Recovering Scans ===")
    
    conn = sqlite3.connect('matrix.db')
    cursor = conn.cursor()
    
    # 1. Fix mixed case types
    print("Normalizing scan types...")
    cursor.execute("UPDATE scans SET scan_type='github_sast' WHERE scan_type='GITHUB_SAST'")
    conn.commit()
    print(f"Fixed {cursor.rowcount} rows.")
    
    # 2. Get pending scans
    print("Fetching pending scans...")
    cursor.execute("SELECT id, scan_type FROM scans WHERE status='PENDING'")
    rows = cursor.fetchall()
    
    conn.close()
    
    print(f"Found {len(rows)} pending scans.")
    
    # 3. Enqueue
    for row in rows:
        scan_id = row[0]
        scan_type = row[1]
        print(f"Enqueuing Scan {scan_id} ({scan_type})...")
        
        try:
            job_id = enqueue_scan(scan_id)
            if job_id:
                print(f"✅ Enqueued: {job_id}")
            else:
                print(f"❌ Failed to enqueue {scan_id}")
        except Exception as e:
            print(f"❌ Error enqueuing {scan_id}: {e}")

if __name__ == "__main__":
    fix_and_recover()
