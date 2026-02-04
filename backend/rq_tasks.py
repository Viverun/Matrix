"""
RQ Task Definitions for Matrix Security Scanner.

This module defines the background tasks that are executed by RQ workers.
Tasks are queued from the API and executed asynchronously by worker processes.
"""
import asyncio
from datetime import datetime, timezone
from typing import Optional
from redis import Redis
from rq import Queue, cancel_job
from sqlalchemy import select

from core.database import async_session_maker
from core.logger import get_logger
# Import all models to ensure SQLAlchemy registry is fully initialized
# This prevents "failed to locate a name" errors in worker processes
from models.user import User
from models.user_settings import UserSettings
from models.scan import Scan, ScanStatus
from models.vulnerability import Vulnerability
from agents.orchestrator import AgentOrchestrator

# Initialize logger
logger = get_logger(__name__)


def get_redis_connection() -> Redis:
    """
    Get Redis connection for RQ.
    
    Returns:
        Redis connection instance
    """
    from config import get_settings
    settings = get_settings()
    
    redis_url = getattr(settings, 'redis_url', 'redis://localhost:6379')
    try:
        from urllib.parse import urlparse
        parsed = urlparse(redis_url)
        safe_netloc = parsed.hostname or "unknown"
        if parsed.port:
            safe_netloc = f"{safe_netloc}:{parsed.port}"
        safe_path = parsed.path or ""
        logger.info(f"[RQ] Using Redis: {parsed.scheme}://{safe_netloc}{safe_path}")
    except Exception:
        logger.info("[RQ] Using Redis: <unparsed>")
    return Redis.from_url(redis_url)


def get_scan_queue() -> Queue:
    """
    Get the scan queue for enqueuing jobs.
    
    Returns:
        RQ Queue instance for scans
    """
    return Queue('scans', connection=get_redis_connection())


def run_scan_job(scan_id: int) -> dict:
    """
    Execute a security scan as an RQ job.
    
    This is the main entry point for scan execution. It runs in a separate
    worker process and handles the full scan lifecycle.
    
    Args:
        scan_id: ID of the scan to execute
        
    Returns:
        Dictionary with scan results summary
    """
    logger.info(f"[RQ Worker] Starting scan job for ID: {scan_id}")
    
    try:
        # Force re-initialization of database engine for this job's loop
        from core.database import db_config
        db_config.engine = None
        db_config.session_maker = None
        
        # Use asyncio.run for robust loop and resource management
        result = asyncio.run(_execute_scan_async(scan_id))
        return result
            
    except Exception as e:
        logger.error(f"[RQ Worker] Critical error in scan job {scan_id}: {str(e)}", exc_info=True)
        raise
        
        # Mark scan as failed in a new loop
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(_mark_scan_failed(scan_id, str(e)))
            loop.close()
        except Exception as mark_error:
            logger.error(f"[RQ Worker] Failed to mark scan as failed: {mark_error}")
        
        raise


async def _execute_scan_async(scan_id: int) -> dict:
    """
    Async implementation of scan execution.
    """
    # Create fresh orchestrator for this specific event loop
    orchestrator = AgentOrchestrator()
    
    try:
        logger.info(f"[RQ Worker] Running async scan for ID: {scan_id}")
        
        async with async_session_maker() as db:
            # Fetch scan record
            result = await db.execute(
                select(Scan).where(Scan.id == scan_id)
            )
            scan = result.scalar_one_or_none()
            
            if not scan:
                logger.error(f"[RQ Worker] Scan {scan_id} not found")
                return {"error": f"Scan {scan_id} not found"}
            
            try:
                # Update status to RUNNING
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.now(timezone.utc)
                scan.progress = 0
                await db.commit()
                
                logger.info(f"[RQ Worker] Starting scan execution for {scan.target_url}")
                
                # Setup progress callback
                async def progress_callback(progress: int, status_message: str):
                    try:
                        # Use a fresh session for progress updates
                        async with async_session_maker() as progress_db:
                            progress_result = await progress_db.execute(
                                select(Scan).where(Scan.id == scan_id)
                            )
                            p_scan = progress_result.scalar_one_or_none()
                            if p_scan:
                                p_scan.progress = progress
                                p_scan.status_message = status_message
                                
                                # Update scanned files if available
                                if orchestrator.scan_context and orchestrator.scan_context.scanned_files:
                                    p_scan.scanned_files = orchestrator.scan_context.scanned_files
                                    
                                await progress_db.commit()
                    except Exception as pe:
                        logger.error(f"Progress update failed: {pe}")

                orchestrator.on_progress = progress_callback
                
                # Execute scan
                results = await orchestrator.run_scan(
                    scan.target_url,
                    agents_enabled=scan.agents_enabled,
                    scan_id=scan.id,
                    custom_headers=scan.custom_headers,
                    custom_cookies=scan.custom_cookies
                )
                
                # Refresh scan object
                await db.refresh(scan)
                
                # Save vulnerabilities
                for res in results:
                    vulnerability = Vulnerability(
                        scan_id=scan.id,
                        title=res.title,
                        description=res.description,
                        severity=res.severity,
                        vulnerability_type=res.vulnerability_type,
                        url=res.url,
                        parameter=res.parameter,
                        method=res.method,
                        evidence=res.evidence,
                        remediation=res.remediation,
                        remediation_code=res.remediation_code,
                        ai_analysis=res.ai_analysis,
                        owasp_category=res.owasp_category,
                        cwe_id=res.cwe_id,
                        detected_at=res.detected_at or datetime.now(timezone.utc),
                        cvss_score=res.cvss_score,
                        cvss_vector=res.cvss_vector,
                        likelihood=res.likelihood,
                        impact=res.impact,
                        exploit_confidence=res.exploit_confidence,
                        detection_confidence=res.detection_confidence,
                        scope_impact=res.scope_impact
                    )
                    db.add(vulnerability)
                    
                    # Update scan counts
                    scan.increment_vulnerability_count(res.severity.value)
                
                # Calculate OWASP coverage from results (avoids generic relation access)
                coverage = {}
                for res in results:
                    if res.owasp_category:
                        coverage[res.owasp_category] = coverage.get(res.owasp_category, 0) + 1
                scan.owasp_coverage = coverage
                
                # Update final status
                scan.status = ScanStatus.COMPLETED
                scan.progress = 100
                scan.completed_at = datetime.now(timezone.utc)
                scan.total_vulnerabilities = len(results)
                
                # Save scanned files list
                if orchestrator.scan_context and orchestrator.scan_context.scanned_files:
                    scan.scanned_files = orchestrator.scan_context.scanned_files

                await db.commit()

                logger.info(f"[RQ Worker] Scan {scan_id} completed successfully")
                
                return {
                    "scan_id": scan_id,
                    "status": "COMPLETED",
                    "total_vulnerabilities": len(results)
                }
                
            except Exception as e:
                logger.error(f"[RQ Worker] Scan execution failed: {str(e)}", exc_info=True)
                # Ensure we rollback before any other DB operations to fix PendingRollbackError
                try:
                    await db.rollback()
                except Exception as rb_err:
                    logger.error(f"[RQ Worker] Rollback failed: {rb_err}")
                
                # Update scan as failed in a fresh transaction
                try:
                    # Refreshing within the same session after rollback might be tricky,
                    # but since the session is still active we can try one more commit
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(e)
                    scan.completed_at = datetime.now(timezone.utc)
                    await db.commit()
                except Exception as commit_err:
                    logger.error(f"[RQ Worker] Failed to update scan status in current session: {commit_err}")
                    # Last resort: try a fresh session
                    await _mark_scan_failed(scan_id, str(e))
                
                raise
                
    finally:
        await orchestrator.cleanup()
        
        # Comprehensive reset of all loop-dependent core components
        try:
            # 1. Database
            from core.database import db_config
            await db_config.force_dispose()
            
            # 2. Groq AI Manager
            from core.groq_client import groq_manager
            await groq_manager.force_dispose()
            
            # 3. Rate Limiter
            from core.rate_limiter import _global_rate_limiter
            _global_rate_limiter.force_reset()
            
            # 4. Request Cache
            from core.request_cache import _global_cache
            _global_cache.force_reset()
            
            # 5. Evidence Tracker
            from core.evidence_tracker import reset_evidence_tracker
            reset_evidence_tracker()
            
            logger.info("[RQ Worker] All core components reset for next job")
        except Exception as reset_error:
            logger.error(f"[RQ Worker] Error during backend component reset: {reset_error}")


async def _mark_scan_failed(scan_id: int, error_message: str) -> None:
    """
    Mark a scan as failed with error message.
    
    Args:
        scan_id: ID of the scan
        error_message: Error message to store
    """
    async with async_session_maker() as db:
        result = await db.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = result.scalar_one_or_none()
        
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = error_message
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            logger.info(f"[RQ Worker] Marked scan {scan_id} as failed")


def enqueue_scan(scan_id: int, timeout: int = 1800) -> Optional[str]:
    """
    Enqueue a scan job to the RQ queue.
    
    Args:
        scan_id: ID of the scan to execute
        timeout: Job timeout in seconds (default 30 minutes)
        
    Returns:
        Job ID if successfully enqueued, None otherwise
    """
    try:
        queue = get_scan_queue()
        job = queue.enqueue(
            run_scan_job,
            scan_id,
            job_timeout=timeout,
            result_ttl=86400,  # Keep result for 24 hours
            failure_ttl=86400,  # Keep failed job info for 24 hours
            job_id=f"scan_{scan_id}",
            meta={
                "scan_id": scan_id,
                "enqueued_at": datetime.now(timezone.utc).isoformat()
            }
        )
        logger.info(f"[RQ] Enqueued scan job: {job.id}")
        return job.id
        
    except Exception as e:
        logger.error(f"[RQ] Failed to enqueue scan {scan_id}: {str(e)}")
        return None


def get_job_status(job_id: str) -> dict:
    """
    Get the status of an RQ job.
    
    Args:
        job_id: The RQ job ID
        
    Returns:
        Dictionary with job status information
    """
    from rq.job import Job
    
    try:
        job = Job.fetch(job_id, connection=get_redis_connection())
        
        return {
            "job_id": job.id,
            "status": job.get_status(),
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "ended_at": job.ended_at.isoformat() if job.ended_at else None,
            "result": job.result,
            "exc_info": job.exc_info,
            "meta": job.meta,
        }
        
    except Exception as e:
        logger.error(f"[RQ] Failed to fetch job {job_id}: {str(e)}")
        return {"error": str(e)}
def cancel_scan_job(scan_id: int) -> bool:
    """
    Cancel a scan job.
    
    If the job is enqueued, it will be removed.
    If the job is currently running, it will be terminated.
    
    Args:
        scan_id: ID of the scan to cancel
        
    Returns:
        True if the job was found and cancellation was attempted
    """
    try:
        redis_conn = get_redis_connection()
        job_id = f"scan_{scan_id}"
        
        # Terminate the job using RQ's built-in command
        # This handles both queued and running jobs
        cancel_job(job_id, connection=redis_conn)
        
        logger.info(f"[RQ] Cancelled scan job: {job_id}")
        return True
        
    except Exception as e:
        logger.error(f"[RQ] Failed to cancel scan {scan_id}: {str(e)}")
        return False
