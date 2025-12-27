#!/usr/bin/env python
"""
RQ Worker Entry Point for Matrix Security Scanner.

This script starts an RQ worker that processes security scan jobs from Redis.

Usage:
    python rq_worker.py                    # Start worker with default settings
    python rq_worker.py --queues scans     # Process only scan queue
    python rq_worker.py --burst            # Process all jobs and exit
    
Environment:
    REDIS_URL: Redis connection URL (default: redis://localhost:6379)
"""
import os
import sys
import argparse
from datetime import datetime, timezone

# Add backend directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from redis import Redis
from rq import Worker, Queue, SimpleWorker
import platform

from config import get_settings
from core.logger import setup_logging, get_logger

# Initialize logging
setup_logging(level="INFO")
logger = get_logger(__name__)


def get_redis_connection() -> Redis:
    """Get Redis connection from settings."""
    settings = get_settings()
    redis_url = getattr(settings, 'redis_url', 'redis://localhost:6379')
    
    logger.info(f"Connecting to Redis: {redis_url}")
    return Redis.from_url(redis_url)


def main():
    """Main entry point for RQ worker."""
    parser = argparse.ArgumentParser(
        description="Matrix Security Scanner RQ Worker"
    )
    parser.add_argument(
        '--queues', '-q',
        nargs='+',
        default=['scans'],
        help='Queues to process (default: scans)'
    )
    parser.add_argument(
        '--name', '-n',
        default=None,
        help='Worker name (default: auto-generated)'
    )
    parser.add_argument(
        '--burst', '-b',
        action='store_true',
        help='Run in burst mode (process existing jobs and exit)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Adjust logging level if verbose
    if args.verbose:
        setup_logging(level="DEBUG")
    
    # Connect to Redis
    try:
        redis_conn = get_redis_connection()
        redis_conn.ping()
        logger.info("Successfully connected to Redis")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {str(e)}")
        logger.error("Make sure Redis is running and REDIS_URL is correct")
        sys.exit(1)
    
    # Create queues
    queues = [Queue(name, connection=redis_conn) for name in args.queues]
    logger.info(f"Worker will process queues: {args.queues}")
    
    # Generate worker name
    worker_name = args.name or f"matrix-worker-{os.getpid()}"
    
    # Print banner
    print("\n" + "=" * 60)
    print("   MATRIX SECURITY SCANNER - RQ WORKER")
    print("=" * 60)
    print(f"  Worker Name: {worker_name}")
    print(f"  Queues:      {', '.join(args.queues)}")
    print(f"  Burst Mode:  {'Yes' if args.burst else 'No'}")
    print(f"  Started:     {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 60 + "\n")
    
    # Start worker - use SimpleWorker on Windows (no fork support)
    if platform.system() == 'Windows':
        logger.info("Running on Windows - using SimpleWorker (no forking)")
        worker = SimpleWorker(
            queues,
            name=worker_name,
            connection=redis_conn
        )
    else:
        worker = Worker(
            queues,
            name=worker_name,
            log_job_description=True,
            connection=redis_conn
        )
    
    logger.info(f"Starting worker '{worker_name}'...")
    
    try:
        worker.work(
            burst=args.burst,
            logging_level="INFO"
        )
    except KeyboardInterrupt:
        logger.info("Worker stopped by user")
    except Exception as e:
        logger.error(f"Worker error: {str(e)}", exc_info=True)
        raise
    
    logger.info("Worker shutdown complete")


if __name__ == '__main__':
    main()
