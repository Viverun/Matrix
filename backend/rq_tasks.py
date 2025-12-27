"""
RQ Task Definitions for Matrix Security Scanner.

This module defines the background tasks that are executed by RQ workers.
Tasks are queued from the API and executed asynchronously by worker processes.
"""
import asyncio
from datetime import datetime, timezone
from typing import Optional
from redis import Redis
from rq import Queue
from sqlalchemy import select

from core.database import async_session_maker
from core.logger import get_logger
from models.scan import Scan, ScanStatus
from models.vulnerability import Vulnerability
from agents.orchestrator import orchestrator

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
        # Create new event loop for async execution
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(_execute_scan_async(scan_id))
            return result
        finally:
            loop.close()
            
    except Exception as e:
        logger.error(f"[RQ Worker] Critical error in scan job {scan_id}: {str(e)}", exc_info=True)
        
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
    
    Args:
        scan_id: ID of the scan to execute
        
    Returns:
        Dictionary with scan results summary
    """
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
            
            logger.info(f"[RQ Worker] Executing orchestrator for {scan.target_url}")
            
            # Define progress callback
            async def progress_callback(progress: int, status_msg: str):
                scan.progress = progress
                try:
                    await db.commit()
                except Exception:
                    await db.rollback()
            
            orchestrator.on_progress = progress_callback
            
            # Run the orchestrator
            results = await orchestrator.run_scan(
                target_url=scan.target_url,
                agents_enabled=scan.agents_enabled
            )
            
            # Save vulnerabilities
            for res in results:
                vuln = Vulnerability(
                    scan_id=scan.id,
                    vulnerability_type=res.vulnerability_type,
                    severity=res.severity,
                    title=res.title,
                    description=res.description,
                    url=res.url,
                    method=res.method,
                    parameter=res.parameter,
                    evidence=res.evidence,
                    remediation=res.remediation,
                    ai_analysis=res.ai_analysis,
                    ai_confidence=res.confidence,
                    owasp_category=res.owasp_category,
                    cwe_id=res.cwe_id,
                    response_snippet=res.response_snippet,
                    detected_by=res.agent_name,
                    reference_links=res.reference_links,
                    likelihood=res.likelihood,
                    impact=res.impact,
                    exploitability_rationale=res.exploitability_rationale,
                    is_suppressed=res.is_suppressed,
                    is_false_positive=res.is_false_positive,
                    suppression_reason=res.suppression_reason,
                    final_verdict=res.final_verdict,
                    action_required=res.action_required,
                    detection_confidence=res.detection_confidence,
                    exploit_confidence=res.exploit_confidence,
                    scope_impact=res.scope_impact
                )
                db.add(vuln)
            
            # Update scan with results
            scan.total_vulnerabilities = len(results)
            scan.critical_count = sum(1 for r in results if r.severity.value == 'critical')
            scan.high_count = sum(1 for r in results if r.severity.value == 'high')
            scan.medium_count = sum(1 for r in results if r.severity.value == 'medium')
            scan.low_count = sum(1 for r in results if r.severity.value == 'low')
            scan.info_count = sum(1 for r in results if r.severity.value == 'info')
            
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.progress = 100
            
            await db.commit()
            
            logger.info(
                f"[RQ Worker] Scan {scan_id} completed: "
                f"{len(results)} vulnerabilities found"
            )
            
            return {
                "scan_id": scan_id,
                "status": "completed",
                "vulnerabilities_found": len(results),
                "critical": scan.critical_count,
                "high": scan.high_count,
                "medium": scan.medium_count,
                "low": scan.low_count,
            }
            
        except Exception as e:
            logger.error(f"[RQ Worker] Scan execution failed: {str(e)}", exc_info=True)
            
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            
            raise
            
        finally:
            await orchestrator.cleanup()


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
