
import os
import sys
from redis import Redis
from rq import Queue, Worker

# Add current directory to path
sys.path.append(os.getcwd())
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from backend.config import get_settings

def check_redis():
    settings = get_settings()
    print(f"Connecting to Redis: {settings.redis_url}")
    
    try:
        redis_conn = Redis.from_url(settings.redis_url)
        redis_conn.ping()
        print("✅ Successfully connected to Redis")
        
        # Check queues
        q = Queue('scans', connection=redis_conn)
        print(f"Queue 'scans' length: {len(q)}")
        
        # Check jobs
        jobs = q.jobs
        for i, job in enumerate(jobs):
            print(f"  Job {i}: ID={job.id}, Status={job.get_status()}, Created={job.created_at}")
            
        # Check workers
        workers = Worker.all(connection=redis_conn)
        print(f"Total workers: {len(workers)}")
        for i, worker in enumerate(workers):
            print(f"  Worker {i}: Name={worker.name}, Queues={worker.queue_names()}, Key={worker.key}")
            
        # Check registries
        from rq.registry import StartedJobRegistry, FailedJobRegistry, FinishedJobRegistry, ScheduledJobRegistry
        
        registries = {
            "Started": StartedJobRegistry('scans', connection=redis_conn),
            "Failed": FailedJobRegistry('scans', connection=redis_conn),
            "Finished": FinishedJobRegistry('scans', connection=redis_conn),
            "Scheduled": ScheduledJobRegistry('scans', connection=redis_conn)
        }
        
        for name, registry in registries.items():
            ids = registry.get_job_ids()
            print(f"{name} jobs ({len(ids)}):")
            for jid in ids:
                print(f"  - {jid}")
                if name == "Failed":
                    from rq.job import Job
                    try:
                        job = Job.fetch(jid, connection=redis_conn)
                        print(f"    Error: {job.exc_info}")
                    except:
                        pass
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    check_redis()
