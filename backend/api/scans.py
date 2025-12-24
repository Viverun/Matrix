"""
Scan management API routes.
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from datetime import datetime

from core.database import get_db
from models.user import User
from models.scan import Scan, ScanStatus
from models.vulnerability import Vulnerability, Severity
from schemas.scan import ScanCreate, ScanResponse, ScanListResponse
from schemas.scan import ScanCreate, ScanResponse, ScanListResponse
from api.deps import get_current_user
from workers import run_scan_task

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new security scan."""
    # Normalize target URL - strip whitespace and ensure scheme
    target_url = scan_data.target_url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"
    
    # Create scan record
    new_scan = Scan(
        target_url=target_url,
        target_name=scan_data.target_name,
        scan_type=scan_data.scan_type,
        agents_enabled=scan_data.agents_enabled,
        user_id=current_user.id,
        status=ScanStatus.PENDING,
    )
    
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)
    
    # Start scan in background
    background_tasks.add_task(run_scan_task, new_scan.id)
    
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
    
    return ScanListResponse(
        items=[ScanResponse.model_validate(scan) for scan in scans],
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size
    )


@router.get("/{scan_id}", response_model=ScanResponse)
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
    
    return ScanResponse.model_validate(scan)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
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


@router.post("/{scan_id}/start", response_model=ScanResponse)
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
    scan.started_at = datetime.utcnow()
    scan.progress = 0
    scan.error_message = None
    
    await db.commit()
    await db.refresh(scan)
    
    # Start actual scan in background
    background_tasks.add_task(run_scan_task, scan.id)
    
    return ScanResponse.model_validate(scan)


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Cancel a running scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if scan.status != ScanStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan with status: {scan.status.value}"
        )
    
    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.utcnow()
    
    await db.commit()
    await db.refresh(scan)
    
    return ScanResponse.model_validate(scan)
