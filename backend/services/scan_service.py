"""
Scan Service - Orchestrates the complete scanning workflow.
"""
import asyncio
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models.scan import Scan, ScanStatus
from models.vulnerability import Vulnerability, Severity, VulnerabilityType
from agents.orchestrator import AgentOrchestrator
from agents.sql_injection_agent import SQLInjectionAgent
from agents.xss_agent import XSSAgent
from agents.auth_agent import AuthenticationAgent
from agents.api_security_agent import APISecurityAgent
from agents.base_agent import AgentResult
from scanner.target_analyzer import TargetAnalyzer


class ScanService:
    """
    Service that manages the complete scanning workflow.
    
    Coordinates:
    - Target analysis
    - Agent execution
    - Result storage
    - Progress tracking
    """
    
    def __init__(self):
        """Initialize the scan service."""
        self.orchestrator = AgentOrchestrator()
        self.analyzer = TargetAnalyzer()
        
        # Register available agents
        self._register_agents()
    
    def _register_agents(self):
        """Register all available security agents."""
        agents = [
            SQLInjectionAgent(),
            XSSAgent(),
            AuthenticationAgent(),
            APISecurityAgent(),
        ]
        
        for agent in agents:
            self.orchestrator.register_agent(agent)
    
    async def run_scan(
        self,
        scan_id: int,
        db: AsyncSession,
        progress_callback: Optional[callable] = None
    ):
        """
        Execute a complete security scan.
        
        Args:
            scan_id: ID of the scan to execute
            db: Database session
            progress_callback: Optional callback for progress updates
        """
        # Get scan from database
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        
        if not scan:
            print(f"[ScanService] Scan {scan_id} not found")
            return
        
        try:
            # Update status to running
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            scan.progress = 0
            await db.commit()
            
            # Set up progress callback
            async def on_progress(progress: int, status: str):
                scan.progress = progress
                await db.commit()
                if progress_callback:
                    await progress_callback(progress, status)
            
            self.orchestrator.on_progress = on_progress
            
            # Phase 1: Analyze target
            print(f"[ScanService] Analyzing target: {scan.target_url}")
            analysis = await self.analyzer.analyze(scan.target_url)
            
            # Store technology stack
            scan.technology_stack = analysis.technology_stack
            await db.commit()
            
            # Convert endpoints to dict format
            endpoints = [e.to_dict() for e in analysis.endpoints]
            
            # Add form-based endpoints
            for form in analysis.forms:
                endpoints.append({
                    "url": form["action"],
                    "method": form["method"],
                    "params": {inp["name"]: inp.get("value", "") for inp in form["inputs"]},
                })
            
            # Phase 2: Run security agents
            print(f"[ScanService] Running security agents...")
            results = await self.orchestrator.run_scan(
                target_url=scan.target_url,
                agents_enabled=scan.agents_enabled or None,
                endpoints=endpoints,
                technology_stack=analysis.technology_stack
            )
            
            # Phase 3: Store vulnerabilities
            vuln_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }
            
            for agent_result in results:
                if agent_result.is_vulnerable:
                    vuln = self._create_vulnerability(agent_result, scan_id)
                    db.add(vuln)
                    
                    # Update counts
                    vuln_counts[agent_result.severity.value] += 1
            
            # Update scan with results
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.progress = 100
            scan.total_vulnerabilities = sum(vuln_counts.values())
            scan.critical_count = vuln_counts["critical"]
            scan.high_count = vuln_counts["high"]
            scan.medium_count = vuln_counts["medium"]
            scan.low_count = vuln_counts["low"]
            scan.info_count = vuln_counts["info"]
            
            await db.commit()
            
            print(f"[ScanService] Scan {scan_id} completed. Found {scan.total_vulnerabilities} vulnerabilities.")
            
        except Exception as e:
            print(f"[ScanService] Scan {scan_id} failed: {e}")
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()
            await db.commit()
            raise
        
        finally:
            # Cleanup
            await self.analyzer.close()
    
    def _create_vulnerability(
        self,
        result: AgentResult,
        scan_id: int
    ) -> Vulnerability:
        """
        Create a Vulnerability database object from an AgentResult.
        
        Args:
            result: Agent scan result
            scan_id: Associated scan ID
            
        Returns:
            Vulnerability database object
        """
        return Vulnerability(
            scan_id=scan_id,
            vulnerability_type=result.vulnerability_type,
            severity=result.severity,
            cvss_score=result.cvss_score,
            url=result.url,
            parameter=result.parameter,
            method=result.method,
            title=result.title,
            description=result.description,
            evidence=result.evidence,
            request_data=result.request_data,
            response_snippet=result.response_snippet,
            ai_confidence=result.confidence,
            ai_analysis=result.ai_analysis,
            remediation=result.remediation,
            remediation_code=result.remediation_code,
            reference_links=result.reference_links,
            owasp_category=result.owasp_category,
            cwe_id=result.cwe_id,
            detected_by=result.agent_name,
            detected_at=result.detected_at,
        )


# Background task function for running scans
async def run_scan_task(scan_id: int, db_url: str):
    """
    Background task to run a scan.
    
    Args:
        scan_id: ID of scan to execute
        db_url: Database connection URL
    """
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    
    engine = create_async_engine(db_url)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as session:
        service = ScanService()
        await service.run_scan(scan_id, session)
    
    await engine.dispose()


# Singleton instance
scan_service = ScanService()
