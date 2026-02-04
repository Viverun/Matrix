"""
Scan management API routes.

Scans are executed asynchronously using a distributed worker queue (RQ + Redis).
Falls back to FastAPI BackgroundTasks if Redis is unavailable.
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from datetime import datetime, timezone

from core.database import get_db
from core.logger import get_logger
from models.user import User
from models.scan import Scan, ScanStatus
from models.vulnerability import Vulnerability, Severity
from schemas.scan import ScanCreate, ScanResponse, ScanListResponse
from api.deps import get_current_user

# Initialize logger
logger = get_logger(__name__)

# Initialize RQ functions as None - will be set if available
enqueue_scan = None
get_job_status = None
cancel_scan_job = None
RQ_AVAILABLE = False

# Try to import RQ functions
try:
    from rq_tasks import enqueue_scan, get_job_status, cancel_scan_job
    RQ_AVAILABLE = True
    logger.info("RQ task queue available - using distributed workers")
except (ImportError, ModuleNotFoundError) as e:
    logger.warning(f"RQ import failed: {e}")
    logger.warning("Falling back to FastAPI BackgroundTasks for scan execution")




router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new security scan.
    
    Scans are queued for asynchronous execution via the RQ worker queue.
    Falls back to FastAPI BackgroundTasks if Redis is unavailable.
    """
    # Normalize target URL - strip whitespace and ensure scheme
    target_url = scan_data.target_url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"
    
    # Validate WAF evasion consent
    # WAF evasion requires explicit consent acknowledgment
    enable_waf_evasion = False
    waf_consent_at = None
    
    if scan_data.enable_waf_evasion:
        if not scan_data.waf_evasion_consent:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "WAF evasion requires explicit consent. "
                    "You must acknowledge the risks by setting waf_evasion_consent=true. "
                    "WARNING: This may trigger security alerts on target systems."
                )
            )
        enable_waf_evasion = True
        waf_consent_at = datetime.now(timezone.utc)
        logger.warning(
            f"WAF evasion ENABLED for scan by user {current_user.id} - consent given",
            extra={"target": target_url, "user_id": current_user.id}
        )
    
    # Create scan record
    new_scan = Scan(
        target_url=target_url,
        target_name=scan_data.target_name,
        scan_type=scan_data.scan_type,
        agents_enabled=scan_data.agents_enabled,
        user_id=current_user.id,
        status=ScanStatus.PENDING,
        enable_waf_evasion=enable_waf_evasion,
        waf_evasion_consent=scan_data.waf_evasion_consent,
        waf_evasion_consent_at=waf_consent_at,
        custom_headers=scan_data.custom_headers,
        custom_cookies=scan_data.custom_cookies,
    )
    
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)
    
    logger.info(f"Scan {new_scan.id} created for target: {target_url}")
    
    # LOGGING: Audit manual authentication usage (Keys only)
    if new_scan.custom_headers:
        logger.info(
            f"Scan {new_scan.id} initialized with custom headers: {list(new_scan.custom_headers.keys())}"
        )
    if new_scan.custom_cookies:
        logger.info(
            f"Scan {new_scan.id} initialized with custom cookies: {list(new_scan.custom_cookies.keys())}"
        )
    
    # Queue scan for execution
    from workers import _run_scan_async
    if RQ_AVAILABLE and enqueue_scan:
        try:
            job_id = enqueue_scan(new_scan.id)
            if job_id:
                logger.info(f"Scan {new_scan.id} enqueued with job ID: {job_id}")
            else:
                # Fallback if enqueue fails
                logger.warning(f"RQ enqueue failed for scan {new_scan.id}, using BackgroundTasks")
                background_tasks.add_task(_run_scan_async, new_scan.id)
        except Exception as e:
            logger.error(f"Exception enqueueing scan {new_scan.id}: {e}", exc_info=True)
            background_tasks.add_task(_run_scan_async, new_scan.id)
    else:
        # Fallback to BackgroundTasks
        if not RQ_AVAILABLE:
            logger.info(f"RQ not available, queuing scan {new_scan.id} via BackgroundTasks")
        background_tasks.add_task(_run_scan_async, new_scan.id)
    
    return ScanResponse.model_validate(new_scan)




@router.get("/", response_model=ScanListResponse)
async def list_scans(
    page: int = 1,
    size: int = 20,
    status: Optional[ScanStatus] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List user's scans with pagination."""
    # Base query
    query = select(Scan).where(Scan.user_id == current_user.id)
    
    # Apply status filter
    if status:
        query = query.where(Scan.status == status)
    
    # Count total
    count_query = select(func.count()).select_from(Scan).where(Scan.user_id == current_user.id)
    if status:
        count_query = count_query.where(Scan.status == status)
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination
    offset = (page - 1) * size
    query = query.order_by(Scan.created_at.desc()).offset(offset).limit(size)
    
    result = await db.execute(query)
    scans = result.scalars().all()
    
    # Explicitly handle scanned_files for each scan
    scan_responses = []
    for scan in scans:
        response = ScanResponse.model_validate(scan)
        if hasattr(scan, 'scanned_files') and scan.scanned_files is not None:
            response.scanned_files = scan.scanned_files
        scan_responses.append(response)
    
    return ScanListResponse(
        items=scan_responses,
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size
    )


@router.get("/{scan_id}/", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get a specific scan by ID."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Create response with explicit scanned_files handling
    response_data = ScanResponse.model_validate(scan)
    # Ensure scanned_files is populated from the database model
    if hasattr(scan, 'scanned_files') and scan.scanned_files is not None:
        response_data.scanned_files = scan.scanned_files
    return response_data


@router.delete("/{scan_id}/", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete a scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    await db.delete(scan)
    await db.commit()


@router.post("/{scan_id}/start/", response_model=ScanResponse)
async def start_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Start a pending scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if scan.status not in [ScanStatus.PENDING, ScanStatus.FAILED]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot start scan with status: {scan.status.value}"
        )
    
    # Update status
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(timezone.utc)
    scan.progress = 0
    scan.error_message = None
    
    await db.commit()
    await db.refresh(scan)
    
    logger.info(f"Starting scan {scan_id} for target: {scan.target_url}")
    
    # Queue scan for execution
    if RQ_AVAILABLE:
        job_id = enqueue_scan(scan.id)
        if job_id:
            logger.info(f"Scan {scan.id} enqueued with job ID: {job_id}")
        else:
            logger.warning(f"RQ enqueue failed for scan {scan.id}, using BackgroundTasks")
            background_tasks.add_task(run_scan_task, scan.id)
    else:
        background_tasks.add_task(run_scan_task, scan.id)
        logger.info(f"Scan {scan.id} queued via BackgroundTasks (fallback)")
    
    return ScanResponse.model_validate(scan)



@router.post("/{scan_id}/cancel/", response_model=ScanResponse)
async def cancel_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Cancel a running or pending scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Allow cancelling if background task exists (RUNNING or PENDING)
    if scan.status not in [ScanStatus.RUNNING, ScanStatus.PENDING]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan with status: {scan.status.value}"
        )
    
    # Update DB status
    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.now(timezone.utc)
    
    await db.commit()
    await db.refresh(scan)
    
    # Attempt to cancel the background task
    if RQ_AVAILABLE and cancel_scan_job:
        try:
            cancelled = cancel_scan_job(scan_id)
            if cancelled:
                logger.info(f"Background job cancelled for scan {scan_id}")
        except Exception as e:
            logger.warning(f"Failed to cancel scan job: {e}")
            
    return ScanResponse.model_validate(scan)
