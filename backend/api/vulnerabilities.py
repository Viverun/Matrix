"""
Vulnerability API routes.

Provides endpoints for listing, viewing, and updating vulnerability findings.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional

from core.database import get_db
from core.logger import get_logger
from models.user import User
from models.scan import Scan
from models.vulnerability import Vulnerability, Severity
from schemas.vulnerability import (
    VulnerabilityResponse, 
    VulnerabilityUpdate, 
    VulnerabilityListResponse,
    VulnerabilitySummary
)
from api.deps import get_current_user

logger = get_logger(__name__)

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get("/", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    scan_id: Optional[int] = None,
    page: int = 1,
    size: int = 50,
    severity: Optional[Severity] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List vulnerabilities with filters."""
    # Build query
    query = select(Vulnerability)
    
    # Filter by scan_id if provided
    if scan_id:
        # Verify scan belongs to user
        scan_result = await db.execute(
            select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
        )
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
             raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )
        query = query.where(Vulnerability.scan_id == scan_id)
    else:
        # If no scan_id, ensure we only start form user's scans
        # Join with Scan table to filter by user_id
        query = query.join(Scan).where(Scan.user_id == current_user.id)
    
    if severity:
        query = query.where(Vulnerability.severity == severity)
    
    # Count total
    # Use subquery for count to respect filters
    # Simplify: execute separate count query
    if scan_id:
        count_query = select(func.count()).select_from(Vulnerability).where(Vulnerability.scan_id == scan_id)
    else:
        count_query = select(func.count()).select_from(Vulnerability).join(Scan).where(Scan.user_id == current_user.id)
        
    if severity:
        count_query = count_query.where(Vulnerability.severity == severity)
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination and ordering
    offset = (page - 1) * size
    query = query.order_by(Vulnerability.severity).offset(offset).limit(size)
    
    result = await db.execute(query)
    vulnerabilities = result.scalars().all()
    
    return VulnerabilityListResponse(
        items=[VulnerabilityResponse.model_validate(v) for v in vulnerabilities],
        total=total,
        page=page,
        size=size
    )


@router.get("/scan/{scan_id}/summary", response_model=VulnerabilitySummary)
async def get_vulnerability_summary(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get vulnerability count summary for a scan."""
    # Verify scan belongs to user
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = scan_result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Count by severity
    counts = {}
    for sev in Severity:
        count_query = select(func.count()).select_from(Vulnerability).where(
            Vulnerability.scan_id == scan_id,
            Vulnerability.severity == sev,
            Vulnerability.is_false_positive == False
        )
        result = await db.execute(count_query)
        counts[sev.value] = result.scalar()
    
    return VulnerabilitySummary(
        total=sum(counts.values()),
        critical=counts.get("critical", 0),
        high=counts.get("high", 0),
        medium=counts.get("medium", 0),
        low=counts.get("low", 0),
        info=counts.get("info", 0)
    )


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vuln_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get a specific vulnerability by ID."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vulnerability = result.scalar_one_or_none()
    
    if not vulnerability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    
    # Verify scan belongs to user
    scan_result = await db.execute(
        select(Scan).where(
            Scan.id == vulnerability.scan_id, 
            Scan.user_id == current_user.id
        )
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    
    return VulnerabilityResponse.model_validate(vulnerability)


@router.patch("/{vuln_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(
    vuln_id: int,
    update_data: VulnerabilityUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update vulnerability status (mark as false positive, verified, fixed)."""
    logger.info(f"Vulnerability update request: {vuln_id} by user {current_user.id}")
    
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vulnerability = result.scalar_one_or_none()
    
    if not vulnerability:
        logger.warning(f"Vulnerability not found: {vuln_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    
    # Verify scan belongs to user
    scan_result = await db.execute(
        select(Scan).where(
            Scan.id == vulnerability.scan_id, 
            Scan.user_id == current_user.id
        )
    )
    if not scan_result.scalar_one_or_none():
        logger.warning(f"Unauthorized access to vulnerability {vuln_id} by user {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    
    # Apply updates
    changes = []
    if update_data.is_false_positive is not None:
        vulnerability.is_false_positive = update_data.is_false_positive
        changes.append(f"false_positive={update_data.is_false_positive}")
    if update_data.is_verified is not None:
        vulnerability.is_verified = update_data.is_verified
        changes.append(f"verified={update_data.is_verified}")
    if update_data.is_fixed is not None:
        vulnerability.is_fixed = update_data.is_fixed
        changes.append(f"fixed={update_data.is_fixed}")
    
    await db.commit()
    await db.refresh(vulnerability)
    
    logger.info(f"Vulnerability {vuln_id} updated: {', '.join(changes)}")
    
    return VulnerabilityResponse.model_validate(vulnerability)

