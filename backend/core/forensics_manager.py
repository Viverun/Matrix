import hashlib
import json
import logging
import os
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import async_session_maker
from models.forensic import ForensicRecord, ForensicTimeline, ForensicArtifact
from models.scan import Scan

logger = logging.getLogger(__name__)

class ForensicManager:
    """
    Manager responsible for the Digital Forensics lifecycle.
    Handles immutable logging, hashing, and evidence bundling.
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ForensicManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        
        # Use /tmp for ephemeral storage on containerized environments
        # Falls back to ./forensic_bundles for local development
        if os.path.exists('/tmp'):
            self.export_dir = '/tmp/forensic_bundles'
        else:
            self.export_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'forensic_bundles')
        
        # Ensure directory exists and is writable
        try:
            os.makedirs(self.export_dir, mode=0o755, exist_ok=True)
            logger.info(f"Forensic bundles directory: {self.export_dir}")
        except Exception as e:
            logger.warning(f"Could not create forensic_bundles directory: {e}")
            # Fallback to /tmp as last resort
            self.export_dir = '/tmp'

    def _calculate_hash(self, data: Union[str, bytes, Dict[str, Any]]) -> str:
        """Generate SHA-256 hash for various data types."""
        if isinstance(data, dict):
            # Sort keys for consistent hashing
            data_st = json.dumps(data, sort_keys=True).encode("utf-8")
        elif isinstance(data, str):
            data_st = data.encode("utf-8")
        else:
            data_st = data
            
        return hashlib.sha256(data_st).hexdigest()

    async def initialize_forensic_session(self, scan_id: int, db: AsyncSession) -> Optional[ForensicRecord]:
        """
        Initialize a new forensic record for a scan.
        Activated automatically when a scan starts.
        """
        try:
            # Check if record already exists
            result = await db.execute(select(ForensicRecord).where(ForensicRecord.scan_id == scan_id))
            record = result.scalar_one_or_none()
            
            if record:
                logger.info(f"Forensic session already exists for scan {scan_id}")
                return record

            # Gather environment metadata
            import sys
            import platform
            env_metadata = {
                "python_version": sys.version,
                "os": platform.system(),
                "os_release": platform.release(),
                "machine": platform.machine(),
                "timestamp_utc": datetime.now(timezone.utc).isoformat()
            }

            record = ForensicRecord(
                scan_id=scan_id,
                system_version="1.0.0", # Matrix version
                environment_metadata=env_metadata,
                integrity_status="VALID"
            )
            db.add(record)
            await db.flush() # Get the ID
            
            # Initial event
            await self.log_timeline_event(
                scan_id=scan_id,
                event_type="SCAN_INITIALIZED",
                source="ForensicManager",
                description=f"Automated forensic layer activated for scan {scan_id}.",
                db=db
            )
            
            logger.info(f"Initialized forensic record {record.evidence_id} for scan {scan_id}")
            return record

        except Exception as e:
            logger.error(f"Failed to initialize forensic session for scan {scan_id}: {e}")
            return None

    async def log_timeline_event(
        self, 
        scan_id: int, 
        event_type: str, 
        source: str, 
        description: str,
        db: AsyncSession,
        vuln_id: Optional[int] = None,
        art_id: Optional[int] = None
    ) -> Optional[ForensicTimeline]:
        """Log an immutable event to the forensic timeline."""
        try:
            # Get forensic record ID
            res = await db.execute(select(ForensicRecord.id).where(ForensicRecord.scan_id == scan_id))
            rec_id = res.scalar_one_or_none()
            
            if not rec_id:
                # If record doesn't exist, try to initialize it first
                rec = await self.initialize_forensic_session(scan_id, db)
                if not rec:
                    return None
                rec_id = rec.id

            # Calculate hash of event data for future integrity verification
            event_data = f"{event_type}|{source}|{description}|{vuln_id}|{art_id}"
            h = self._calculate_hash(event_data)

            event = ForensicTimeline(
                forensic_record_id=rec_id,
                event_type=event_type,
                source_module=source,
                description=description,
                vulnerability_id=vuln_id,
                artifact_id=art_id,
                event_hash=h
            )
            db.add(event)
            await db.flush()
            
            return event

        except Exception as e:
            logger.error(f"Failed to log forensic event for scan {scan_id}: {e}")
            return None

    async def record_artifact(
        self,
        scan_id: int,
        name: str,
        artifact_type: str,
        data: Union[str, bytes],
        db: AsyncSession,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[ForensicArtifact]:
        """Record an immutable artifact from the scan."""
        try:
            res = await db.execute(select(ForensicRecord.id).where(ForensicRecord.scan_id == scan_id))
            rec_id = res.scalar_one_or_none()
            
            if not rec_id:
                return None

            # Calculate hash of raw data
            h = self._calculate_hash(data)
            
            # Convert to string if bytes
            if isinstance(data, bytes):
                try:
                    raw_data_str = data.decode('utf-8', errors='replace')
                except:
                    raw_data_str = f"BINARY_DATA:{len(data)} bytes"
            else:
                raw_data_str = data

            artifact = ForensicArtifact(
                forensic_record_id=rec_id,
                name=name,
                artifact_type=artifact_type,
                raw_data=raw_data_str,
                metadata_json=metadata or {},
                sha256_hash=h
            )
            db.add(artifact)
            await db.flush()

            # Log this in timeline
            await self.log_timeline_event(
                scan_id=scan_id,
                event_type="ARTIFACT_COLLECTED",
                source="ForensicManager",
                description=f"Artifact captured: {name} (Type: {artifact_type})",
                db=db,
                art_id=artifact.id
            )
            
            # Update hash manifest in record
            result = await db.execute(select(ForensicRecord).where(ForensicRecord.scan_id == scan_id))
            record = result.scalar_one()
            
            manifest = record.hash_manifest or {}
            manifest[artifact.artifact_evidence_id] = h
            record.hash_manifest = manifest
            
            return artifact

        except Exception as e:
            logger.error(f"Failed to record artifact for scan {scan_id}: {e}")
            return None

    async def finalize_forensic_session(self, scan_id: int, db: AsyncSession):
        """Finalize the forensic record and generate the sum summary hash."""
        try:
            result = await db.execute(select(ForensicRecord).where(ForensicRecord.scan_id == scan_id))
            record = result.scalar_one_or_none()
            
            if not record:
                return

            await self.log_timeline_event(
                scan_id=scan_id,
                event_type="SCAN_COMPLETED",
                source="ForensicManager",
                description="Scan lifecycle completed. Finalizing forensic manifest.",
                db=db
            )

            # Generate whole-scan hash (hash of the manifest + metadata)
            scan_data = {
                "evidence_id": record.evidence_id,
                "scan_id": record.scan_id,
                "manifest": record.hash_manifest,
                "env": record.environment_metadata
            }
            record.scan_hash = self._calculate_hash(scan_data)
            
            logger.info(f"Finalized forensic session for scan {scan_id}. Scan Hash: {record.scan_hash}")
            
        except Exception as e:
            logger.error(f"Failed to finalize forensic session for scan {scan_id}: {e}")

    async def generate_bundle(self, scan_id: int, db: AsyncSession) -> Optional[str]:
        """Generate a ZIP bundle containing all forensic evidence for a scan."""
        try:
            # Fetch record, timeline, and artifacts
            result = await db.execute(select(ForensicRecord).where(ForensicRecord.scan_id == scan_id))
            record = result.scalar_one_or_none()
            if not record:
                return None
            
            timeline_res = await db.execute(select(ForensicTimeline).where(ForensicTimeline.forensic_record_id == record.id))
            timeline = timeline_res.scalars().all()
            
            artifact_res = await db.execute(select(ForensicArtifact).where(ForensicArtifact.forensic_record_id == record.id))
            artifacts = artifact_res.scalars().all()
            
            # Create bundle filename
            bundle_filename = f"forensic_bundle_{record.evidence_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            bundle_path = os.path.join(self.export_dir, bundle_filename)
            
            with zipfile.ZipFile(bundle_path, 'w') as zipf:
                # 1. Manifest / Report
                report_data = {
                    "evidence_id": record.evidence_id,
                    "scan_id": record.scan_id,
                    "integrity_status": record.integrity_status,
                    "scan_hash": record.scan_hash,
                    "environment": record.environment_metadata,
                    "timeline": [e.to_dict() for e in timeline],
                    "artifacts": [a.to_dict() for a in artifacts],
                    "manifest": record.hash_manifest
                }
                zipf.writestr("forensic_report.json", json.dumps(report_data, indent=2))
                
                # 2. Individual Artifacts
                for art in artifacts:
                    file_ext = "txt"
                    if art.artifact_type == "HTTP_RESPONSE": file_ext = "http"
                    elif art.artifact_type == "SOURCE_CODE": file_ext = "py"
                    
                    filename = f"artifacts/{art.artifact_evidence_id}_{art.name.replace(' ', '_')}.{file_ext}"
                    zipf.writestr(filename, art.raw_data or "")
            
            # Verify bundle was created
            if not os.path.exists(bundle_path):
                raise Exception(f"Bundle file was not created at {bundle_path}")
            
            # Update record
            record.bundle_path = bundle_path
            record.last_exported_at = datetime.now(timezone.utc)
            await db.commit()
            
            logger.info(f"Successfully generated forensic bundle for scan {scan_id} at {bundle_path}")
            return bundle_path
        except Exception as e:
            logger.error(f"Failed to generate forensic bundle for scan {scan_id}: {e}", exc_info=True)
            return None

    async def generate_summary_report(self, scan_id: int, db: AsyncSession) -> Optional[Dict[str, Any]]:
        """
        Produce a comprehensive, structured forensic summary report for the scan.
        Aggregates timeline, artifacts, and AI analysis into a unified insight document.
        """
        try:
            # 1. Fetch all related data
            record_res = await db.execute(select(ForensicRecord).where(ForensicRecord.scan_id == scan_id))
            record = record_res.scalar_one_or_none()
            if not record:
                return None
            
            scan_res = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = scan_res.scalar_one_or_none()
            
            artifact_res = await db.execute(select(ForensicArtifact).where(ForensicArtifact.forensic_record_id == record.id))
            artifacts = artifact_res.scalars().all()
            
            timeline_res = await db.execute(select(ForensicTimeline).where(ForensicTimeline.forensic_record_id == record.id).order_by(ForensicTimeline.timestamp))
            timeline = timeline_res.scalars().all()

            # 2. Analyze findings from artifacts metadata
            findings = []
            for art in artifacts:
                metadata = art.metadata_json or {}
                if metadata.get("is_vulnerable") is True or metadata.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:
                    findings.append({
                        "id": art.artifact_evidence_id,
                        "title": art.name,
                        "type": art.artifact_type,
                        "severity": metadata.get("severity", "INFO"),
                        "impact": metadata.get("business_impact", "No data"),
                        "root_cause": metadata.get("root_cause", "Pending investigation"),
                        "remediation": metadata.get("remediation", "Manual fix required"),
                        "owasp": metadata.get("compliance_mapping", {}).get("owasp", "N/A"),
                        "cwe": metadata.get("compliance_mapping", {}).get("cwe", "N/A")
                    })

            # 3. Aggregate metrics
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in findings:
                sev = f["severity"].upper()
                if sev in severity_counts:
                    severity_counts[sev] += 1

            # 4. Construct the deep report
            report = {
                "header": {
                    "evidence_id": record.evidence_id,
                    "target": scan.target_url if scan else "Unknown",
                    "status": "COMPLETED",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "integrity_hash": record.scan_hash
                },
                "executive_summary": {
                    "total_findings": len(findings),
                    "critical_issues": severity_counts["CRITICAL"],
                    "high_issues": severity_counts["HIGH"],
                    "risk_posture": "CRITICAL" if severity_counts["CRITICAL"] > 0 else "HIGH" if severity_counts["HIGH"] > 0 else "STABLE",
                    "summary_statement": f"Scan {record.evidence_id} detected {len(findings)} noteworthy security artifacts. " + 
                                       (f"Urgent action is required to address {severity_counts['CRITICAL']} critical vulnerabilities." if severity_counts['CRITICAL'] > 0 else "No immediate critical risks detected.")
                },
                "vulnerability_landscape": {
                    "severity_distribution": severity_counts,
                    "key_findings": findings[:5], # Top findings
                },
                "compliance_check": {
                    "owasp_top_10_coverage": list(set([f["owasp"] for f in findings if f["owasp"] != "N/A"])),
                    "frameworks": ["OWASP 2021", "CWE", "NIST CSF (Partial)"]
                },
                "evidence_integrity": {
                    "status": record.integrity_status,
                    "artifact_count": len(artifacts),
                    "timeline_events": len(timeline)
                }
            }

            return report

        except Exception as e:
            logger.error(f"Failed to generate forensic summary report for scan {scan_id}: {e}")
            return None

    async def get_artifact_data(self, artifact_id: str, db: AsyncSession) -> Optional[tuple[str, str, str]]:
        """Get artifact raw data, name, and content type for download."""
        try:
            query = select(ForensicArtifact).where(ForensicArtifact.artifact_evidence_id == artifact_id)
            result = await db.execute(query)
            artifact = result.scalar_one_or_none()
            
            if not artifact:
                return None
                
            return artifact.raw_data, artifact.name, artifact.content_type
        except Exception as e:
            logger.error(f"Failed to get artifact data for {artifact_id}: {e}")
            return None

    async def generate_artifact_report(self, artifact_id: str, db: AsyncSession) -> Optional[tuple[str, str]]:
        """Generate a comprehensive text report for a single forensic artifact."""
        try:
            query = select(ForensicArtifact).where(ForensicArtifact.artifact_evidence_id == artifact_id)
            result = await db.execute(query)
            artifact = result.scalar_one_or_none()
            
            if not artifact:
                return None
                
            metadata = artifact.metadata_json or {}
            
            report = f"""MATRIX DIGITAL FORENSICS - EVIDENCE REPORT
==========================================
ARTIFACT ID: {artifact.artifact_evidence_id}
NAME: {artifact.name}
TYPE: {artifact.artifact_type}
TIMESTAMP: {artifact.collection_time.strftime('%Y-%m-%d %H:%M:%S UTC')}
INTEGRITY HASH (SHA-256): {artifact.sha256_hash}
------------------------------------------

[1] FORENSIC ANALYSIS
---------------------
{metadata.get('ai_reasoning') or metadata.get('ai_analysis') or 'No AI analysis generated for this artifact.'}

[2] TECHNICAL METADATA
----------------------
Severity: {metadata.get('severity', 'N/A')}
Confidence: {metadata.get('confidence', 'N/A')}%
Vulnerability Type: {metadata.get('vulnerability_type', 'N/A')}
Root Cause: {metadata.get('root_cause', 'N/A')}
Business Impact: {metadata.get('business_impact', 'N/A')}

[3] COMPLIANCE MAPPING
----------------------
OWASP: {metadata.get('compliance_mapping', {}).get('owasp', 'N/A')}
CWE: {metadata.get('compliance_mapping', {}).get('cwe', 'N/A')}
NIST: {metadata.get('compliance_mapping', {}).get('nist', 'N/A')}

[4] RAW EVIDENCE STREAM
-----------------------
{artifact.raw_data or 'No raw evidence captured.'}

==========================================
END OF FORENSIC REPORT
"""
            return report, artifact.name
        except Exception as e:
            logger.error(f"Failed to generate artifact report for {artifact_id}: {e}")
            return None

# Global singleton
forensic_manager = ForensicManager()
