"""
Agent Orchestrator - Coordinates multiple security agents for comprehensive scanning.
"""
import asyncio
from typing import List, Dict, Any, Optional, Type
from datetime import datetime
from enum import Enum
from urllib.parse import urljoin


from .base_agent import BaseSecurityAgent, AgentResult
from .github_agent import GithubSecurityAgent
from models.scan import Scan, ScanStatus
from models.vulnerability import Vulnerability, Severity, VulnerabilityType


class ScanPhase(str, Enum):
    """Phases of the scanning process."""
    RECONNAISSANCE = "reconnaissance"
    ACTIVE_SCANNING = "active_scanning"
    ANALYSIS = "analysis"
    REPORTING = "reporting"


class AgentOrchestrator:
    """
    Orchestrator that manages and coordinates multiple security agents.
    
    Responsible for:
    - Managing agent lifecycle
    - Coordinating scan execution
    - Aggregating results
    - Progress tracking
    """
    
    def __init__(self):
        """Initialize the orchestrator."""
        self.agents: Dict[str, BaseSecurityAgent] = {}
        self.results: List[AgentResult] = []
        self.current_phase: ScanPhase = ScanPhase.RECONNAISSANCE
        self.progress: int = 0
        self.is_running: bool = False
        self.should_cancel: bool = False
        
        # Register default agents
        self.register_agent(GithubSecurityAgent())
        self.results: List[AgentResult] = []
        self.current_phase: ScanPhase = ScanPhase.RECONNAISSANCE
        self.progress: int = 0
        self.is_running: bool = False
        self.should_cancel: bool = False
        
        # Progress callbacks
        self.on_progress: Optional[callable] = None
        self.on_vulnerability_found: Optional[callable] = None
    
    def register_agent(self, agent: BaseSecurityAgent) -> None:
        """
        Register a security agent with the orchestrator.
        
        Args:
            agent: Security agent instance to register
        """
        self.agents[agent.agent_name] = agent
        print(f"[Orchestrator] Registered agent: {agent.agent_name}")
    
    def unregister_agent(self, agent_name: str) -> None:
        """
        Unregister a security agent.
        
        Args:
            agent_name: Name of the agent to remove
        """
        if agent_name in self.agents:
            del self.agents[agent_name]
            print(f"[Orchestrator] Unregistered agent: {agent_name}")
    
    async def run_scan(
        self,
        target_url: str,
        agents_enabled: List[str] = None,
        endpoints: List[Dict[str, Any]] = None,
        technology_stack: List[str] = None
    ) -> List[AgentResult]:
        """
        Execute a comprehensive security scan.
        
        Args:
            target_url: Base URL of the target
            agents_enabled: List of agent names to use (None = all)
            endpoints: List of endpoints to test
            technology_stack: Detected technologies
            
        Returns:
            List of all vulnerabilities found
        """
        self.is_running = True
        self.should_cancel = False
        self.results = []
        self.progress = 0
        
        print(f"[Orchestrator] Starting scan of {target_url}")
        print(f"[Orchestrator] Enabled agents: {agents_enabled or 'all'}")
        
        try:
            # Phase 1: Reconnaissance
            self.current_phase = ScanPhase.RECONNAISSANCE
            await self._update_progress(5, "Analyzing target...")
            
            if endpoints is None:
                if "github.com" in target_url:
                    # Skip common discovery for GitHub URLs
                    endpoints = [{"url": target_url, "method": "GIT", "params": {}}]
                else:
                    endpoints = await self._discover_endpoints(target_url)
            
            print(f"[ORCHESTRATOR DEBUG] Target: {target_url}")
            print(f"[ORCHESTRATOR DEBUG] Endpoints: {len(endpoints)}")
            
            if technology_stack is None:
                if "github.com" in target_url:
                    technology_stack = ["GitHub Repository", "Source Code"]
                else:
                    technology_stack = await self._detect_technology(target_url)
            
            await self._update_progress(15, "Discovery complete")
            
            # Phase 2: Active Scanning
            self.current_phase = ScanPhase.ACTIVE_SCANNING
            
            # Determine which agents to run
            agents_to_run = []
            
            # Auto-enable Github agent for github URLs if not specified
            is_github_target = "github.com" in target_url
            
            for name, agent in self.agents.items():
                if agents_enabled is None:
                    if is_github_target:
                        # Only run GitHub agent for repos by default
                        if name == "github_security":
                            agents_to_run.append(agent)
                    else:
                        # Run web agents for regular URLs
                        if name != "github_security":
                            agents_to_run.append(agent)
                elif name in agents_enabled:
                    agents_to_run.append(agent)
            
            print(f"[ORCHESTRATOR DEBUG] Agents to run: {[a.agent_name for a in agents_to_run]}")
            
            if not agents_to_run:
                print("[ORCHESTRATOR DEBUG] No agents enabled! Check agents_enabled param or registered agents.")
                return []
            
            # Calculate progress per agent
            progress_per_agent = 70 // len(agents_to_run)
            current_progress = 15
            
            # Run agents concurrently in groups
            agent_tasks = []
            for agent in agents_to_run:
                if self.should_cancel:
                    break
                
                task = self._run_agent(
                    agent, 
                    target_url, 
                    endpoints, 
                    technology_stack
                )
                agent_tasks.append(task)
            
            # Execute all agents concurrently
            agent_results = await asyncio.gather(*agent_tasks, return_exceptions=True)
            
            # Process results
            for i, result in enumerate(agent_results):
                if isinstance(result, Exception):
                    print(f"[Orchestrator] Agent error: {result}")
                elif isinstance(result, list):
                    self.results.extend(result)
                
                current_progress += progress_per_agent
                await self._update_progress(current_progress, f"Completed {i+1}/{len(agents_to_run)} agents")
            
            # Phase 3: Analysis
            self.current_phase = ScanPhase.ANALYSIS
            await self._update_progress(90, "Analyzing results...")
            
            # Deduplicate and sort results
            self.results = self._deduplicate_results(self.results)
            self.results.sort(key=lambda x: (
                list(Severity).index(x.severity),
                -x.confidence
            ))
            
            # Phase 4: Complete
            self.current_phase = ScanPhase.REPORTING
            await self._update_progress(100, "Scan complete")
            
            print(f"[Orchestrator] Scan complete. Found {len(self.results)} vulnerabilities")
            
            return self.results
            
        except Exception as e:
            print(f"[Orchestrator] Scan error: {e}")
            raise
        finally:
            self.is_running = False
    
    async def _run_agent(
        self,
        agent: BaseSecurityAgent,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str]
    ) -> List[AgentResult]:
        """
        Run a single agent.
        
        Args:
            agent: Agent to run
            target_url: Target URL
            endpoints: Endpoints to test
            technology_stack: Technology stack
            
        Returns:
            Agent results
        """
        print(f"[Orchestrator] Running {agent.agent_name}...")
        
        try:
            results = await agent.scan(
                target_url=target_url,
                endpoints=endpoints,
                technology_stack=technology_stack
            )
            
            # Notify about found vulnerabilities
            for result in results:
                if result.is_vulnerable and self.on_vulnerability_found:
                    await self.on_vulnerability_found(result)
            
            print(f"[Orchestrator] {agent.agent_name} found {len(results)} issues")
            return results
            
        except Exception as e:
            print(f"[Orchestrator] {agent.agent_name} error: {e}")
            return []
    
    async def _discover_endpoints(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Discover endpoints on the target.
        
        Args:
            target_url: Base URL to scan
            
        Returns:
            List of discovered endpoints
        """
        # Ensure target_url has scheme
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"
            
        # Ensure target_url doesn't have duplicate slashes when joining
        base_url = target_url.rstrip("/")
        
        endpoints = [
            {"url": base_url, "method": "GET", "params": {}},
            {"url": f"{base_url}/xss", "method": "GET", "params": {"q": "<script>alert(1)</script>"}},
            {"url": f"{base_url}/sqli", "method": "GET", "params": {"id": "1' OR '1'='1"}},
            {"url": f"{base_url}/login", "method": "GET", "params": {}},
            {"url": f"{base_url}/login", "method": "POST", "params": {"username": "", "password": ""}},
            {"url": f"{base_url}/api", "method": "GET", "params": {}},
            {"url": f"{base_url}/search", "method": "GET", "params": {"q": ""}},
        ]

        
        return endpoints
    
    async def _detect_technology(self, target_url: str) -> List[str]:
        """
        Detect technology stack of the target.
        
        Args:
            target_url: URL to analyze
            
        Returns:
            List of detected technologies
        """
        # Would implement actual technology detection
        return ["Web Application", "Unknown Framework"]
    
    def _deduplicate_results(self, results: List[AgentResult]) -> List[AgentResult]:
        """
        Remove duplicate vulnerability findings.
        
        Args:
            results: List of results to deduplicate
            
        Returns:
            Deduplicated results
        """
        seen = set()
        unique_results = []
        
        for result in results:
            key = (
                result.vulnerability_type,
                result.url,
                result.parameter,
                result.method
            )
            
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        return unique_results
    
    async def _update_progress(self, progress: int, status: str) -> None:
        """
        Update scan progress.
        
        Args:
            progress: Progress percentage (0-100)
            status: Status message
        """
        self.progress = progress
        print(f"[Orchestrator] Progress: {progress}% - {status}")
        
        if self.on_progress:
            await self.on_progress(progress, status)
    
    def cancel_scan(self) -> None:
        """Request cancellation of the current scan."""
        self.should_cancel = True
        print("[Orchestrator] Cancellation requested")
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        for agent in self.agents.values():
            await agent.close()
        
        self.agents.clear()
        print("[Orchestrator] Cleanup complete")
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of scan results.
        
        Returns:
            Summary dictionary
        """
        summary = {
            "total": len(self.results),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "by_type": {},
            "by_agent": {}
        }
        
        for result in self.results:
            # Count by severity
            severity_key = result.severity.value
            summary[severity_key] = summary.get(severity_key, 0) + 1
            
            # Count by type
            type_key = result.vulnerability_type.value
            summary["by_type"][type_key] = summary["by_type"].get(type_key, 0) + 1
            
            # Count by agent
            summary["by_agent"][result.agent_name] = summary["by_agent"].get(result.agent_name, 0) + 1
        
        return summary


# Singleton orchestrator instance
orchestrator = AgentOrchestrator()
