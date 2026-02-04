from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List, Dict, Any, Optional
import os

from core.database import get_db
from models.forensic import ForensicRecord, ForensicTimeline, ForensicArtifact
from models.scan import Scan
from models.user import User
from core.forensics_manager import forensic_manager
from api.deps import get_current_user

router = APIRouter(prefix="/forensics", tags=["Forensics"])

@router.get("/")
async def list_forensic_records(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(10, ge=1),
    offset: int = Query(0, ge=0)
):
    """List all forensic records across all scans."""
    try:
        query = select(ForensicRecord).order_by(desc(ForensicRecord.created_at)).limit(limit).offset(offset)
        result = await db.execute(query)
        records = result.scalars().all()
        
        return [record.to_dict() for record in records]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{scan_id}/")
async def get_forensic_record(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get summarized forensic record for a specific scan."""
    query = select(ForensicRecord).where(ForensicRecord.scan_id == scan_id)
    result = await db.execute(query)
    record = result.scalar_one_or_none()
    
    if not record:
        raise HTTPException(status_code=404, detail="Forensic record not found for this scan")
        
    return {
        **record.to_dict(),
        "environment_metadata": record.environment_metadata,
        "hash_manifest": record.hash_manifest,
        "scan_hash": record.scan_hash
    }

@router.get("/{scan_id}/report/")
async def get_forensic_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get comprehensive forensic summary report for a scan."""
    report = await forensic_manager.generate_summary_report(scan_id, db)
    if not report:
        raise HTTPException(status_code=404, detail="Forensic report could not be generated")
    return report

@router.get("/{scan_id}/timeline/")
async def get_forensic_timeline(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get the full chronological forensic timeline for a scan."""
    # Get record id first
    rec_query = select(ForensicRecord.id).where(ForensicRecord.scan_id == scan_id)
    rec_res = await db.execute(rec_query)
    rec_id = rec_res.scalar_one_or_none()
    
    if not rec_id:
        raise HTTPException(status_code=404, detail="Forensic record not found")
        
    timeline_query = select(ForensicTimeline).where(ForensicTimeline.forensic_record_id == rec_id).order_by(ForensicTimeline.timestamp)
    result = await db.execute(timeline_query)
    events = result.scalars().all()
    
    return [event.to_dict() for event in events]

@router.get("/{scan_id}/artifacts/")
async def list_forensic_artifacts(scan_id: int, db: AsyncSession = Depends(get_db)):
    """List all artifacts collected for a scan."""
    rec_query = select(ForensicRecord.id).where(ForensicRecord.scan_id == scan_id)
    rec_res = await db.execute(rec_query)
    rec_id = rec_res.scalar_one_or_none()
    
    if not rec_id:
        raise HTTPException(status_code=404, detail="Forensic record not found")
        
    art_query = select(ForensicArtifact).where(ForensicArtifact.forensic_record_id == rec_id)
    art_res = await db.execute(art_query)
    artifacts = art_res.scalars().all()
    
    return [art.to_dict() for art in artifacts]

@router.get("/{scan_id}/artifacts/{artifact_id}/")
async def get_artifact_detail(scan_id: int, artifact_id: str, db: AsyncSession = Depends(get_db)):
    """Get raw data and metadata for a specific artifact."""
    query = select(ForensicArtifact).where(ForensicArtifact.artifact_evidence_id == artifact_id)
    result = await db.execute(query)
    artifact = result.scalar_one_or_none()
    
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
        
    return {
        **artifact.to_dict(),
        "raw_data": artifact.raw_data,
        "metadata": artifact.metadata_json
    }

@router.get("/{scan_id}/export/bundle/")
async def export_forensic_bundle(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Generate and download a forensic ZIP bundle."""
    bundle_path = await forensic_manager.generate_bundle(scan_id, db)
    if not bundle_path:
        raise HTTPException(status_code=500, detail="Failed to generate forensic bundle")
    
    if not os.path.exists(bundle_path):
        raise HTTPException(
            status_code=500, 
            detail=f"Forensic bundle file not found at {bundle_path}. Possible permission or storage issue."
        )
        
    return FileResponse(
        path=bundle_path,
        filename=os.path.basename(bundle_path),
        media_type="application/zip"
    )

@router.get("/{scan_id}/artifacts/{artifact_id}/download/")
async def download_artifact(scan_id: int, artifact_id: str, db: AsyncSession = Depends(get_db)):
    """Download a comprehensive forensic report for a specific artifact."""
    report_data = await forensic_manager.generate_artifact_report(artifact_id, db)
    if not report_data:
        raise HTTPException(status_code=404, detail="Artifact not found or report generation failed")
        
    report_text, name = report_data
    
    # Return as an attachment
    return Response(
        content=report_text,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="FORENSIC_REPORT_{artifact_id}_{name.replace(" ", "_")}.txt"',
            "X-Content-Type-Options": "nosniff"
        }
    )


@router.post("/{scan_id}/artifacts/{artifact_id}/report-issue/")
async def report_issue_github(scan_id: int, artifact_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Report a finding as a GitHub Issue using user's GitHub token.
    Falls back to system token if user hasn't configured one.
    """
    # 1. Fetch artifact
    query = select(ForensicArtifact).where(ForensicArtifact.artifact_evidence_id == artifact_id)
    result = await db.execute(query)
    artifact = result.scalar_one_or_none()
    
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
        
    metadata = artifact.metadata_json or {}
    github_url = metadata.get("url", "") or metadata.get("repository", "")
    
    if "github.com" not in github_url:
        raise HTTPException(status_code=400, detail="Only GitHub findings can be reported as issues.")

    # 2. Get GitHub token (user's token first, then system token)
    from agents.github_agent import GithubSecurityAgent
    from api.github_settings import get_user_github_token
    from config import get_settings
    
    github_token = await get_user_github_token(current_user.id, db)
    if not github_token:
        # Fall back to system token
        settings = get_settings()
        github_token = settings.github_token
        if not github_token or "your_github_token" in github_token:
            raise HTTPException(
                status_code=403,
                detail="No GitHub token configured. Please add your GitHub token in Settings."
            )
    
    agent = GithubSecurityAgent(github_token=github_token)
    owner_repo = agent._parse_github_url(github_url)
    if not owner_repo:
        raise HTTPException(status_code=400, detail="Invalid GitHub URL")
        
    owner, repo = owner_repo
    
    # 3. Format the description from metadata
    import json
    
    # Parse ai_analysis if it's JSON
    description = metadata.get('ai_analysis', '')
    if description and isinstance(description, str) and description.strip().startswith('{'):
        try:
            parsed = json.loads(description)
            # Extract human-readable description
            description = (
                parsed.get('description') or 
                parsed.get('reasoning') or 
                parsed.get('title') or 
                description
            )
        except json.JSONDecodeError:
            pass  # Keep original if parsing fails
    
    if not description:
        description = 'Please review the vulnerability details in the Matrix Forensics dashboard.'
    
    # 4. Create Issue
    issue_body = f"""### 🛡️ Matrix Security Finding
**Type**: {metadata.get('vulnerability_type', 'Security Finding')}
**Severity**: {metadata.get('severity', 'High').upper()}
**File**: {metadata.get('file_path')}

#### Description
{description}

---
*Reported by Matrix Autopilot*"""

    result = await agent.create_github_issue(
        owner=owner,
        repo=repo,
        title=f"Security Finding: {artifact.name}",
        body=issue_body
    )
    
    if result["status"] == "failed":
        raise HTTPException(status_code=500, detail=result.get("error"))
        
    # 4. Update artifact metadata
    metadata["issue_url"] = result["issue_url"]
    metadata["issue_number"] = result["issue_number"]
    metadata["status"] = "reported"
    
    # We need to inform SQLAlchemy that JSON changed
    artifact.metadata_json = dict(metadata)
    db.add(artifact)
    await db.commit()
    
    return result

@router.post("/{scan_id}/artifacts/{artifact_id}/self-heal/")
async def self_heal_artifact(scan_id: int, artifact_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Trigger GitHub Autopilot to automatically fix a finding via Pull Request.
    Uses user's GitHub token. Only applicable for GITHUB_SECURITY artifacts with valid file paths.
    """
    # 1. Fetch artifact to get metadata
    query = select(ForensicArtifact).where(ForensicArtifact.artifact_evidence_id == artifact_id)
    result = await db.execute(query)
    artifact = result.scalar_one_or_none()
    
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
        
    metadata = artifact.metadata_json or {}
    
    # 2. Verify it's a GitHub finding
    github_url = metadata.get("url", "")
    if not github_url or "github.com" not in github_url:
        # Fallback check for repository field
        github_url = metadata.get("repository", "")
        
    if "github.com" not in github_url:
        raise HTTPException(
            status_code=400, 
            detail="Self-healing is currently only available for GitHub source code findings."
        )
        
    file_path = metadata.get("file_path")
    if not file_path:
        raise HTTPException(
            status_code=400, 
            detail="Artifact metadata is missing file path information (required for patching)."
        )
        
    # 3. Get GitHub token (user's token first, then system token)
    from agents.github_agent import GithubSecurityAgent
    from api.github_settings import get_user_github_token
    from config import get_settings
    
    github_token = await get_user_github_token(current_user.id, db)
    if not github_token:
        # Fall back to system token
        settings = get_settings()
        github_token = settings.github_token
        if not github_token or "your_github_token" in github_token:
            raise HTTPException(
                status_code=403,
                detail="No GitHub token configured. Please add your GitHub token in Settings."
            )
    
    # 4. Parse owner and repo

    agent = GithubSecurityAgent(github_token=github_token)
    owner_repo = agent._parse_github_url(github_url)
    if not owner_repo:
        raise HTTPException(status_code=400, detail="Could not parse GitHub repository from metadata URL.")
        
    owner, repo = owner_repo
    
    # 5. Execute Self-Healing (Generates patch -> Creates Branch -> Pushes Code -> Opens PR)
    result = await agent.execute_self_healing(
        owner=owner,
        repo=repo,
        file_path=file_path,
        vulnerability_title=artifact.name,
        vulnerability_id=artifact_id,
        issue_number=metadata.get("issue_number")
    )
    
    if result["status"] == "failed":
        raise HTTPException(
            status_code=500, 
            detail=f"Self-healing failed: {result.get('error')}"
        )
    
    # Update status to fixed
    metadata["status"] = "fixed"
    metadata["pr_url"] = result["pr_url"]
    artifact.metadata_json = dict(metadata)
    db.add(artifact)
    await db.commit()
        
    return result
