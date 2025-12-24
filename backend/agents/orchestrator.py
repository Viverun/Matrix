"""
Agent Orchestrator - Coordinates multiple security agents for comprehensive scanning.
"""
import asyncio
import re
from typing import List, Dict, Any, Optional, Type, Set
from datetime import datetime
from enum import Enum
from urllib.parse import urljoin
from difflib import SequenceMatcher
from dataclasses import dataclass, field


from .base_agent import BaseSecurityAgent, AgentResult
from .github_agent import GithubSecurityAgent
from models.scan import Scan, ScanStatus
from models.vulnerability import Vulnerability, Severity, VulnerabilityType
from core.scan_context import ScanContext, AgentPhase


@dataclass
class AgentNode:
    """Node in the agent dependency graph."""
    agent: BaseSecurityAgent
    phase: AgentPhase
    dependencies: List[str] = field(default_factory=list)  # List of agent names this depends on
    timeout_seconds: int = 300  # 5 minutes default
    max_retries: int = 2


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
        self.agent_nodes: Dict[str, AgentNode] = {}  # Dependency graph nodes
        self.results: List[AgentResult] = []
        self.current_phase: ScanPhase = ScanPhase.RECONNAISSANCE
        self.progress: int = 0
        self.is_running: bool = False
        self.should_cancel: bool = False
        
        # Error tracking
        self.failed_agents: List[Dict[str, Any]] = []
        
        # Scan context for inter-agent communication
        self.scan_context: Optional[ScanContext] = None
        
        # Progress callbacks
        self.on_progress: Optional[callable] = None
        self.on_vulnerability_found: Optional[callable] = None
        
        # Register default agents with dependencies
        self._register_default_agents()
    
    def _register_default_agents(self):
        """Register default agents with dependency configuration."""
        # Import agents here to avoid circular imports
        from .sql_injection_agent import SQLInjectionAgent
        from .xss_agent import XSSAgent
        from .auth_agent import AuthenticationAgent
        from .api_security_agent import APISecurityAgent
        from .csrf_agent import CSRFAgent
        from .ssrf_agent import SSRFAgent
        from .command_injection_agent import CommandInjectionAgent
        
        # GitHub agent - runs first in recon phase (no dependencies)
        github_agent = GithubSecurityAgent()
        self.register_agent(
            github_agent,
            phase=AgentPhase.RECONNAISSANCE,
            dependencies=[],
            timeout_seconds=600  # 10 minutes for repo scanning
        )
        
        # Authentication agent - runs early, informs other agents
        auth_agent = AuthenticationAgent()
        self.register_agent(
            auth_agent,
            phase=AgentPhase.DISCOVERY,
            dependencies=["github_security"],
            timeout_seconds=300
        )
        
        # API Security agent - foundational checks
        api_agent = APISecurityAgent()
        self.register_agent(
            api_agent,
            phase=AgentPhase.DISCOVERY,
            dependencies=["github_security"],
            timeout_seconds=300
        )
        
        # SQL Injection agent
        sqli_agent = SQLInjectionAgent()
        self.register_agent(
            sqli_agent,
            phase=AgentPhase.EXPLOITATION,
            dependencies=["authentication", "api_security"],
            timeout_seconds=600
        )
        
        # XSS agent
        xss_agent = XSSAgent()
        self.register_agent(
            xss_agent,
            phase=AgentPhase.EXPLOITATION,
            dependencies=["authentication", "api_security"],
            timeout_seconds=600
        )
        
        # CSRF agent
        csrf_agent = CSRFAgent()
        self.register_agent(
            csrf_agent,
            phase=AgentPhase.EXPLOITATION,
            dependencies=["authentication"],
            timeout_seconds=300
        )
        
        # SSRF agent
        ssrf_agent = SSRFAgent()
        self.register_agent(
            ssrf_agent,
            phase=AgentPhase.EXPLOITATION,
            dependencies=["api_security"],
            timeout_seconds=300
        )
        
        # Command Injection agent
        cmd_agent = CommandInjectionAgent()
        self.register_agent(
            cmd_agent,
            phase=AgentPhase.EXPLOITATION,
            dependencies=["api_security"],
            timeout_seconds=300
        )
    
    def register_agent(
        self,
        agent: BaseSecurityAgent,
        phase: AgentPhase = AgentPhase.EXPLOITATION,
        dependencies: List[str] = None,
        timeout_seconds: int = 300
    ) -> None:
        """
        Register a security agent with the orchestrator.
        
        Args:
            agent: Security agent instance to register
            phase: Execution phase for this agent
            dependencies: List of agent names this agent depends on
            timeout_seconds: Max execution time for this agent
        """
        self.agents[agent.agent_name] = agent
        self.agent_nodes[agent.agent_name] = AgentNode(
            agent=agent,
            phase=phase,
            dependencies=dependencies or [],
            timeout_seconds=timeout_seconds
        )
        print(f"[Orchestrator] Registered agent: {agent.agent_name} (phase: {phase.value})")
    
    def unregister_agent(self, agent_name: str) -> None:
        """
        Unregister a security agent.
        
        Args:
            agent_name: Name of the agent to remove
        """
        if agent_name in self.agents:
            del self.agents[agent_name]
            if agent_name in self.agent_nodes:
                del self.agent_nodes[agent_name]
            print(f"[Orchestrator] Unregistered agent: {agent_name}")
    
    def _route_endpoints_for_agent(
        self,
        agent_name: str,
        all_endpoints: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Filter endpoints relevant for a specific agent.
        
        Args:
            agent_name: Name of the agent
            all_endpoints: All discovered endpoints
            
        Returns:
            Filtered list of relevant endpoints
        """
        # Authentication agent: login/auth endpoints
        if agent_name == "authentication":
            auth_patterns = [r'/login', r'/signin', r'/sign-in', r'/auth', r'/register', r'/signup']
            filtered = [
                ep for ep in all_endpoints
                if any(re.search(pattern, ep["url"], re.IGNORECASE) for pattern in auth_patterns)
            ]
            # If no auth endpoints found, return login endpoint
            return filtered if filtered else [ep for ep in all_endpoints if "/login" in ep["url"].lower()]
        
        # API security agent: API endpoints
        elif agent_name == "api_security":
            api_patterns = [r'/api/', r'/v\d+/', r'\.json', r'/rest/', r'/graphql']
            return [
                ep for ep in all_endpoints
                if any(re.search(pattern, ep["url"], re.IGNORECASE) for pattern in api_patterns)
            ]
        
        # SQL injection agent: endpoints with parameters
        elif agent_name == "sql_injection":
            return [
                ep for ep in all_endpoints
                if ep.get("params") or "?" in ep["url"] or ep["method"] == "POST"
            ]
        
        # XSS agent: endpoints that accept user input
        elif agent_name == "xss":
            return [
                ep for ep in all_endpoints
                if ep.get("params") or "search" in ep["url"].lower() or "q=" in ep["url"]
            ]
        
        # CSRF agent: state-changing endpoints (POST, PUT, DELETE)
        elif agent_name == "csrf":
            return [
                ep for ep in all_endpoints
                if ep.get("method", "GET").upper() in ["POST", "PUT", "DELETE", "PATCH"]
                or any(p in ep["url"].lower() for p in ["/update", "/delete", "/create", "/edit", "/submit"])
            ]
        
        # SSRF agent: endpoints that might fetch external resources
        elif agent_name == "ssrf":
            ssrf_patterns = [r'url', r'link', r'src', r'href', r'path', r'file', r'fetch', r'redirect', r'callback', r'proxy']
            return [
                ep for ep in all_endpoints
                if any(
                    any(re.search(pattern, str(p), re.IGNORECASE) for pattern in ssrf_patterns)
                    for p in ep.get("params", {}).keys()
                ) or any(re.search(pattern, ep["url"], re.IGNORECASE) for pattern in ssrf_patterns)
            ]
        
        # Command Injection agent: endpoints with execution-like parameters
        elif agent_name == "command_injection":
            cmd_patterns = [r'cmd', r'exec', r'command', r'run', r'ping', r'host', r'ip', r'file', r'path']
            return [
                ep for ep in all_endpoints
                if any(
                    any(re.search(pattern, str(p), re.IGNORECASE) for pattern in cmd_patterns)
                    for p in ep.get("params", {}).keys()
                ) or ep.get("params")  # Test any endpoint with params
            ]
        
        # GitHub agent: pass original URL
        elif agent_name == "github_security":
            return all_endpoints
        
        # Default: all endpoints
        return all_endpoints
    
    async def run_scan(
        self,
        target_url: str,
        agents_enabled: List[str] = None,
        endpoints: List[Dict[str, Any]] = None,
        technology_stack: List[str] = None,
        scan_id: int = 0
    ) -> List[AgentResult]:
        """
        Execute a comprehensive security scan using dependency graph.
        
        Args:
            target_url: Base URL of the target
            agents_enabled: List of agent names to use (None = all)
            endpoints: List of endpoints to test
            technology_stack: Detected technologies
            scan_id: ID of the scan in database
            
        Returns:
            List of all vulnerabilities found
        """
        self.is_running = True
        self.should_cancel = False
        self.results = []
        self.progress = 0
        self.failed_agents = []
        
        # Normalize target_url
        if not target_url.startswith(("http://", "https://")):
            target_url = f"http://{target_url}"
        
        # Initialize scan context for inter-agent communication
        self.scan_context = ScanContext(
            scan_id=scan_id,
            target_url=target_url,
            technology_stack=technology_stack or []
        )
        
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
            
            # Store discovered endpoints in context
            self.scan_context.discovered_endpoints = endpoints
            
            print(f"[ORCHESTRATOR] Target: {target_url}")
            print(f"[ORCHESTRATOR] Endpoints: {len(endpoints)}")
            
            if technology_stack is None:
                if "github.com" in target_url:
                    technology_stack = ["GitHub Repository", "Source Code"]
                else:
                    technology_stack = await self._detect_technology(target_url)
            
            self.scan_context.technology_stack = technology_stack
            
            await self._update_progress(15, "Discovery complete")
            
            # Phase 2: Execute agents based on dependency graph
            self.current_phase = ScanPhase.ACTIVE_SCANNING
            
            # Determine which agents to run
            agents_to_run = self._select_agents(target_url, agents_enabled)
            
            print(f"[ORCHESTRATOR] Agents to run: {[a for a in agents_to_run]}")
            
            if not agents_to_run:
                print("[ORCHESTRATOR] No agents enabled!")
                return []
            
            # Execute agents in dependency order with phased execution
            agent_results = await self._execute_agents_graph(
                agents_to_run,
                target_url,
                endpoints,
                technology_stack
            )
            
            # Collect all results
            for result in agent_results:
                if isinstance(result, list):
                    self.results.extend(result)
            
            # Phase 3: Analysis (Intelligence Layer)
            self.current_phase = ScanPhase.ANALYSIS
            await self._update_progress(85, "Applying intelligence layer...")
            
            # Step 1: Validate evidence (auto-downgrade findings without evidence)
            self.results = self._validate_evidence(self.results)
            
            # Step 2: Filter false positives (mark low-confidence/placeholder findings)
            self.results = self._filter_false_positives(self.results)
            
            # Step 3: Correlate findings (aggregate → reason → score)
            self.results = self._correlate_results(self.results)
            
            # Step 4: Apply exploitability gates (downgrade if gates fail)
            self.results = self._apply_exploitability_gates(self.results)
            
            # Step 4: Deduplicate and sort
            await self._update_progress(92, "Deduplicating results...")
            self.results = self._deduplicate_results_similarity(self.results)
            self.results.sort(key=lambda x: (
                list(Severity).index(x.severity),
                -x.confidence
            ))
            
            # Step 5: Calculate scan metrics
            self._calculate_scan_metrics()
            
            # Phase 4: Complete
            self.current_phase = ScanPhase.REPORTING
            await self._update_progress(100, "Scan complete")
            
            print(f"[Orchestrator] Scan complete. Found {len(self.results)} vulnerabilities")
            if self.failed_agents:
                print(f"[Orchestrator] {len(self.failed_agents)} agents failed: {[a['agent'] for a in self.failed_agents]}")
            
            return self.results
            
        except Exception as e:
            print(f"[Orchestrator] Scan error: {e}")
            import traceback
            traceback.print_exc()
            raise
        finally:
            self.is_running = False
    
    def _select_agents(
        self,
        target_url: str,
        agents_enabled: Optional[List[str]]
    ) -> List[str]:
        """
        Select which agents to run based on target and configuration.
        
        Args:
            target_url: Target URL being scanned
            agents_enabled: List of explicitly enabled agents (None = auto-select)
            
        Returns:
            List of agent names to run
        """
        is_github_target = "github.com" in target_url
        
        if agents_enabled is not None:
            # Use explicitly enabled agents
            return [name for name in agents_enabled if name in self.agents]
        
        # Auto-select based on target type
        if is_github_target:
            # Only run GitHub agent for repositories
            return ["github_security"] if "github_security" in self.agents else []
        else:
            # Run all non-GitHub agents for web targets
            return [name for name in self.agents.keys() if name != "github_security"]
    
    async def _execute_agents_graph(
        self,
        agent_names: List[str],
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str]
    ) -> List[List[AgentResult]]:
        """
        Execute agents respecting dependency graph.
        
        Agents are executed in phases based on their dependencies.
        Independent agents in the same phase run concurrently.
        
        Args:
            agent_names: Names of agents to execute
            target_url: Target URL
            endpoints: Endpoints to test
            technology_stack: Detected technologies
            
        Returns:
            List of results from all agents
        """
        all_results = []
        completed_agents: Set[str] = set()
        
        # Group agents by phase
        phases = {
            AgentPhase.RECONNAISSANCE: [],
            AgentPhase.DISCOVERY: [],
            AgentPhase.EXPLOITATION: [],
            AgentPhase.ANALYSIS: []
        }
        
        for agent_name in agent_names:
            if agent_name in self.agent_nodes:
                node = self.agent_nodes[agent_name]
                phases[node.phase].append(agent_name)
        
        # Execute phases sequentially
        phase_progress_start = 15
        phase_progress_range = 75  # 15% to 90%
        total_phases = sum(1 for agents in phases.values() if agents)
        
        current_phase_num = 0
        
        for phase in [AgentPhase.RECONNAISSANCE, AgentPhase.DISCOVERY, AgentPhase.EXPLOITATION, AgentPhase.ANALYSIS]:
            phase_agents = phases[phase]
            if not phase_agents:
                continue
            
            current_phase_num += 1
            progress = phase_progress_start + (current_phase_num / total_phases) * phase_progress_range
            
            print(f"[Orchestrator] Executing {phase.value} phase with {len(phase_agents)} agents")
            await self._update_progress(int(progress), f"Phase: {phase.value}")
            
            # Execute agents in this phase respecting dependencies
            phase_results = await self._execute_phase_agents(
                phase_agents,
                target_url,
                endpoints,
                technology_stack,
                completed_agents
            )
            
            all_results.extend(phase_results)
            completed_agents.update(phase_agents)
        
        return all_results
    
    async def _execute_phase_agents(
        self,
        agent_names: List[str],
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str],
        completed_agents: Set[str]
    ) -> List[List[AgentResult]]:
        """
        Execute agents in a phase, respecting dependencies within the phase.
        
        Args:
            agent_names: Agents to execute in this phase
            target_url: Target URL
            endpoints: Endpoints to test
            technology_stack: Technology stack
            completed_agents: Set of already completed agents
            
        Returns:
            Results from all agents in this phase
        """
        results = []
        remaining = set(agent_names)
        
        while remaining:
            # Find agents whose dependencies are satisfied
            ready_agents = []
            for agent_name in remaining:
                node = self.agent_nodes[agent_name]
                deps_satisfied = all(dep in completed_agents for dep in node.dependencies)
                if deps_satisfied:
                    ready_agents.append(agent_name)
            
            if not ready_agents:
                # Circular dependency or missing dependency
                print(f"[Orchestrator ERROR] Cannot proceed with agents: {remaining}")
                print(f"[Orchestrator ERROR] Completed: {completed_agents}")
                break
            
            # Execute ready agents concurrently
            tasks = []
            for agent_name in ready_agents:
                agent = self.agents[agent_name]
                node = self.agent_nodes[agent_name]
                
                # Route endpoints for this agent
                agent_endpoints = self._route_endpoints_for_agent(agent_name, endpoints)
                
                task = self._run_agent_with_retry(
                    agent,
                    target_url,
                    agent_endpoints,
                    technology_stack,
                    timeout=node.timeout_seconds,
                    max_retries=node.max_retries
                )
                tasks.append(task)
            
            # Wait for all ready agents to complete
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    agent_name = ready_agents[i]
                    print(f"[Orchestrator] Agent {agent_name} failed: {result}")
                    self.failed_agents.append({
                        "agent": agent_name,
                        "error": str(result),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                elif isinstance(result, list):
                    results.append(result)
            
            # Mark as completed and remove from remaining
            completed_agents.update(ready_agents)
            remaining -= set(ready_agents)
        
        return results
    
    async def _run_agent_with_retry(
        self,
        agent: BaseSecurityAgent,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str],
        timeout: int = 300,
        max_retries: int = 2
    ) -> List[AgentResult]:
        """
        Run an agent with timeout and retry logic.
        
        Args:
            agent: Agent to run
            target_url: Target URL
            endpoints: Filtered endpoints for this agent
            technology_stack: Technology stack
            timeout: Timeout in seconds
            max_retries: Maximum retry attempts
            
        Returns:
            Agent results
        """
        retry_count = 0
        last_error = None
        
        while retry_count <= max_retries:
            try:
                print(f"[Orchestrator] Running {agent.agent_name} (attempt {retry_count + 1}/{max_retries + 1})...")
                
                # Run with timeout
                results = await asyncio.wait_for(
                    self._run_agent(agent, target_url, endpoints, technology_stack),
                    timeout=timeout
                )
                
                return results
                
            except asyncio.TimeoutError:
                last_error = f"Timeout after {timeout}s"
                print(f"[Orchestrator] {agent.agent_name} timed out after {timeout}s")
                retry_count += 1
                if retry_count <= max_retries:
                    wait_time = min(2 ** retry_count, 10)  # Exponential backoff, max 10s
                    print(f"[Orchestrator] Retrying {agent.agent_name} in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                    
            except Exception as e:
                last_error = str(e)
                print(f"[Orchestrator] {agent.agent_name} error: {e}")
                retry_count += 1
                if retry_count <= max_retries:
                    wait_time = min(2 ** retry_count, 10)
                    print(f"[Orchestrator] Retrying {agent.agent_name} in {wait_time}s...")
                    await asyncio.sleep(wait_time)
        
        # All retries failed
        raise Exception(f"{agent.agent_name} failed after {max_retries + 1} attempts: {last_error}")
    
    async def _run_agent(
        self,
        agent: BaseSecurityAgent,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str]
    ) -> List[AgentResult]:
        """
        Run a single agent with scan context.
        
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
            # Pass scan context to agent
            results = await agent.scan(
                target_url=target_url,
                endpoints=endpoints,
                technology_stack=technology_stack,
                scan_context=self.scan_context
            )
            
            # Notify about found vulnerabilities
            for result in results:
                if result.is_vulnerable and self.on_vulnerability_found:
                    await self.on_vulnerability_found(result)
            
            print(f"[Orchestrator] {agent.agent_name} found {len(results)} issues")
            return results
            
        except Exception as e:
            print(f"[Orchestrator] {agent.agent_name} error: {e}")
            raise  # Re-raise for retry logic
    
    async def _discover_endpoints(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Discover endpoints on the target.
        
        Args:
            target_url: Base URL to scan
            
        Returns:
            List of discovered endpoints
        """
        from scanner.target_analyzer import TargetAnalyzer
        
        # Ensure target_url has scheme
        if not target_url.startswith(("http://", "https://")):
            target_url = f"http://{target_url}"
        
        try:
            # Use the actual target analyzer
            analyzer = TargetAnalyzer(timeout=30.0, max_depth=2)
            analysis = await analyzer.analyze(target_url)
            await analyzer.close()
            
            # Convert discovered endpoints to dict format
            endpoints = [ep.to_dict() for ep in analysis.endpoints]
            
            print(f"[Orchestrator] Discovered {len(endpoints)} endpoints from target analysis")
            
            # If no endpoints found, add at least the base URL
            if not endpoints:
                endpoints = [{"url": target_url, "method": "GET", "params": {}}]
            
            return endpoints
            
        except Exception as e:
            print(f"[Orchestrator] Error discovering endpoints: {e}")
            # Fallback to basic endpoints
            base_url = target_url.rstrip("/")
            return [
                {"url": base_url, "method": "GET", "params": {}},
            ]
    
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
        Remove duplicate vulnerability findings (legacy method).
        
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
    
    def _calculate_similarity(self, result1: AgentResult, result2: AgentResult) -> float:
        """
        Calculate similarity score between two results.
        
        Args:
            result1: First result
            result2: Second result
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        # Must be same vulnerability type
        if result1.vulnerability_type != result2.vulnerability_type:
            return 0.0
        
        # Compare URLs
        url_similarity = SequenceMatcher(None, result1.url, result2.url).ratio()
        
        # Compare parameters (if both have them)
        param_similarity = 1.0
        if result1.parameter and result2.parameter:
            param_similarity = SequenceMatcher(None, result1.parameter, result2.parameter).ratio()
        elif result1.parameter or result2.parameter:
            # One has parameter, one doesn't
            param_similarity = 0.5
        
        # Compare methods
        method_similarity = 1.0 if result1.method == result2.method else 0.0
        
        # Weighted average
        similarity = (url_similarity * 0.5 + param_similarity * 0.3 + method_similarity * 0.2)
        
        return similarity
    
    def _correlate_results(self, results: List[AgentResult]) -> List[AgentResult]:
        """
        Correlate and escalate vulnerabilities based on chaining.
        
        Example Chains:
        - Reflected XSS + Missing CSP -> Escalate XSS to High/Critical
        - Missing HSTS + Sensitive Cookies -> Escalate Session Hijack risk
        - IDOR + Sensitive Data Exposure -> Escalate to Critical data leak
        """
        if not results:
            return results
            
        print(f"[Orchestrator] Correlating {len(results)} findings...")
        
        # Categorize results by type and URL
        by_type = {}
        by_url = {}
        
        for r in results:
            t = r.vulnerability_type
            if t not in by_type: by_type[t] = []
            by_type[t].append(r)
            
            u = r.url
            if u not in by_url: by_url[u] = []
            by_url[u].append(r)
            
        # 1. XSS + Missing CSP Escalation
        xss_types = [VulnerabilityType.XSS_REFLECTED, VulnerabilityType.XSS_STORED, VulnerabilityType.XSS_DOM]
        for xss_type in xss_types:
            if xss_type in by_type:
                for xss in by_type[xss_type]:
                    # Check if the same URL is missing CSP
                    url_findings = by_url.get(xss.url, [])
                    has_no_csp = any(
                        r.vulnerability_type == VulnerabilityType.SECURITY_MISCONFIG and 
                        "Content-Security-Policy" in r.title
                        for r in url_findings
                    )
                    
                    if has_no_csp:
                        print(f"[Orchestrator] Escalating {xss.title} due to missing CSP")
                        xss.severity = Severity.HIGH if xss.severity == Severity.MEDIUM else xss.severity
                        xss.ai_analysis += "\n\n[Correlation] Severity escalated (confidence: high): Missing Content-Security-Policy (CSP) significantly increases the exploitability and impact of this XSS vulnerability. Attackers can execute arbitrary JavaScript without CSP restrictions."
                        xss.confidence = min(100, xss.confidence + 10)
                        xss.exploitability_rationale = "Directly exploitable. The absence of CSP allows unhindered execution of malicious scripts in the victim's browser context."

        # 2. IDOR + Sensitive Data exposure
        if VulnerabilityType.IDOR in by_type and VulnerabilityType.SENSITIVE_DATA in by_type:
            for idor in by_type[VulnerabilityType.IDOR]:
                for sensitive in by_type[VulnerabilityType.SENSITIVE_DATA]:
                    if idor.url == sensitive.url:
                        print(f"[Orchestrator] Escalating IDOR due to sensitive data exposure")
                        idor.severity = Severity.CRITICAL
                        idor.ai_analysis += f"\n\n[Correlation] Severity escalated (confidence: high): IDOR on this endpoint leads to direct exposure of sensitive data ({sensitive.title}). This chain represents a critical data breach risk."
                        idor.confidence = 100
                        idor.impact = 10.0
                        idor.likelihood = 9.0

        # 3. Missing HSTS + Sensitive Cookies / Session Tokens
        # Check for HSTS issues and correlate with authentication/session findings
        if VulnerabilityType.SECURITY_MISCONFIG in by_type:
            hsts_missing = [
                r for r in by_type[VulnerabilityType.SECURITY_MISCONFIG]
                if "Strict-Transport-Security" in r.title or "HSTS" in r.title
            ]
            
            auth_issues = by_type.get(VulnerabilityType.BROKEN_AUTH, [])
            sensitive_data = by_type.get(VulnerabilityType.SENSITIVE_DATA, [])
            
            for hsts in hsts_missing:
                # Check for auth issues on same URL (insecure cookies, etc.)
                related_auth = [a for a in auth_issues if a.url == hsts.url]
                related_sensitive = [s for s in sensitive_data if s.url == hsts.url]
                
                if related_auth or related_sensitive:
                    print(f"[Orchestrator] Escalating missing HSTS due to session/sensitive data exposure")
                    hsts.severity = Severity.MEDIUM
                    correlation_targets = [a.title for a in related_auth] + [s.title for s in related_sensitive]
                    hsts.ai_analysis += f"\n\n[Correlation] Severity escalated (confidence: medium): Missing HSTS combined with {', '.join(correlation_targets[:2])} creates a session hijacking risk vector via MITM attacks on HTTP downgrade."
                    hsts.confidence = min(95, hsts.confidence + 15)
                    hsts.impact = max(hsts.impact, 6.0)
                    hsts.likelihood = max(hsts.likelihood, 5.0)
                    hsts.exploitability_rationale = "Conditionally exploitable. Requires active MITM position, but the presence of session tokens or sensitive data on this endpoint makes this a meaningful risk."
        
        return results

    def _deduplicate_results_similarity(self, results: List[AgentResult]) -> List[AgentResult]:
        """
        Remove duplicate vulnerability findings using similarity scoring.
        
        Clusters similar findings and merges them, taking the highest
        confidence score and combining evidence.
        
        Args:
            results: List of results to deduplicate
            
        Returns:
            Deduplicated results with merged evidence
        """
        if not results:
            return []
        
        unique_results = []
        processed = set()
        
        for i, result1 in enumerate(results):
            if i in processed:
                continue
            
            # Find all similar results
            similar_indices = [i]
            for j, result2 in enumerate(results[i+1:], start=i+1):
                if j in processed:
                    continue
                
                similarity = self._calculate_similarity(result1, result2)
                
                # Threshold: 85% similar = duplicate
                if similarity >= 0.85:
                    similar_indices.append(j)
                    processed.add(j)
            
            # Merge similar results
            if len(similar_indices) > 1:
                merged = self._merge_results([results[idx] for idx in similar_indices])
                unique_results.append(merged)
            else:
                unique_results.append(result1)
            
            processed.add(i)
        
        print(f"[Orchestrator] Deduplicated {len(results)} → {len(unique_results)} results")
        return unique_results
    
    def _merge_results(self, results: List[AgentResult]) -> AgentResult:
        """
        Merge multiple similar results into one.
        
        Takes the highest confidence, combines evidence, and merges details.
        
        Args:
            results: List of similar results to merge
            
        Returns:
            Merged result
        """
        # Use the result with highest confidence as base
        base = max(results, key=lambda r: r.confidence)
        
        # Aggregate confidence (take maximum)
        max_confidence = max(r.confidence for r in results)
        
        # Combine evidence from all results
        all_evidence = []
        for r in results:
            if r.evidence and r.evidence not in all_evidence:
                all_evidence.append(r.evidence)
        
        combined_evidence = " | ".join(all_evidence) if all_evidence else base.evidence
        
        # Combine AI analysis
        all_analysis = [r.ai_analysis for r in results if r.ai_analysis]
        combined_analysis = " / ".join(set(all_analysis)) if all_analysis else base.ai_analysis
        
        # Create merged result
        merged = AgentResult(
            agent_name=f"{base.agent_name} (+{len(results)-1} similar)",
            vulnerability_type=base.vulnerability_type,
            is_vulnerable=base.is_vulnerable,
            severity=base.severity,
            confidence=max_confidence,
            url=base.url,
            parameter=base.parameter,
            method=base.method,
            title=base.title,
            description=base.description,
            evidence=combined_evidence,
            request_data=base.request_data,
            response_snippet=base.response_snippet,
            ai_analysis=combined_analysis,
            remediation=base.remediation,
            remediation_code=base.remediation_code,
            reference_links=base.reference_links,
            owasp_category=base.owasp_category,
            cwe_id=base.cwe_id,
            detected_at=base.detected_at,
            cvss_score=base.cvss_score,
            likelihood=max(r.likelihood for r in results),
            impact=max(r.impact for r in results),
            exploitability_rationale=base.exploitability_rationale
        )
        
        return merged
    
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
        # We don't clear agents or close their clients here anymore
        # to allow the singleton to persist across scans.
        # Background tasks and context is handled per-scan.
        self.is_running = False
        print("[Orchestrator] Cleanup complete (singleton state preserved)")
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of scan results including failures.
        
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
            "by_agent": {},
            "failed_agents": self.failed_agents,
            "scan_context_summary": {}
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
        
        # Add scan context summary
        if self.scan_context:
            summary["scan_context_summary"] = {
                "discovered_credentials": len(self.scan_context.discovered_credentials),
                "has_database_info": self.scan_context.has_database_info(),
                "session_tokens": len(self.scan_context.session_tokens),
                "authenticated": self.scan_context.authenticated
            }
        
        # Add scan metrics
        if hasattr(self, 'scan_metrics'):
            summary["metrics"] = self.scan_metrics
        
        return summary
    
    # ==================== INTELLIGENCE LAYER ====================
    
    def _validate_evidence(self, results: List[AgentResult]) -> List[AgentResult]:
        """
        Validate that findings have proper evidence.
        
        Auto-downgrades findings without evidence:
        - HIGH/CRITICAL without evidence → MEDIUM
        - MEDIUM without evidence → LOW
        
        Args:
            results: List of findings to validate
            
        Returns:
            Results with adjusted severities
        """
        for result in results:
            has_evidence = bool(
                result.evidence and 
                len(result.evidence.strip()) > 10 and
                result.evidence.lower() not in ["none", "n/a", "not available"]
            )
            
            has_response = bool(
                result.response_snippet and 
                len(result.response_snippet.strip()) > 0
            )
            
            if not has_evidence and not has_response:
                original_severity = result.severity
                
                if result.severity in [Severity.CRITICAL, Severity.HIGH]:
                    result.severity = Severity.MEDIUM
                    result.ai_analysis += f"\n\n[Evidence Gate] Severity downgraded from {original_severity.value} to MEDIUM: Insufficient evidence provided. High-severity findings require concrete request/response evidence."
                    result.confidence = min(result.confidence, 60)
                    print(f"[Orchestrator] Downgraded '{result.title}' due to missing evidence")
                elif result.severity == Severity.MEDIUM:
                    result.severity = Severity.LOW
                    result.ai_analysis += f"\n\n[Evidence Gate] Severity downgraded from MEDIUM to LOW: No concrete evidence provided."
                    result.confidence = min(result.confidence, 50)
        
        return results
    
    def _filter_false_positives(self, results: List[AgentResult]) -> List[AgentResult]:
        """
        Filter out or mark false positive findings based on AI analysis signals.
        
        False Positive Signals:
        1. AI explicitly marked is_vulnerable: false
        2. Confidence score < 30 (very low confidence)
        3. Analysis contains false positive keywords
        4. Evidence is placeholder text (YOUR_API_KEY_HERE, example, etc.)
        
        Args:
            results: List of findings to filter
            
        Returns:
            Filtered results with false positives removed or marked
        """
        filtered_results = []
        
        false_positive_keywords = [
            "not vulnerable",
            "false positive", 
            "placeholder",
            "example value",
            "your_api_key_here",
            "xxx-xxx",
            "not exploitable",
            "properly encoded",
            "correctly sanitized"
        ]
        
        placeholder_patterns = [
            r"YOUR_.*_HERE",
            r"EXAMPLE_.*",
            r"\*\*\*\*",
            r"xxxx",
            r"<YOUR.*>",
            r"\[INSERT.*\]"
        ]
        
        for result in results:
            is_false_positive = False
            fp_reason = None
            
            # Check 1: Very low confidence (AI unsure)
            if result.confidence < 30:
                is_false_positive = True
                fp_reason = f"Very low confidence ({result.confidence}%) indicates insufficient evidence"
            
            # Check 2: False positive keywords in analysis
            analysis_lower = result.ai_analysis.lower()
            for keyword in false_positive_keywords:
                if keyword in analysis_lower:
                    is_false_positive = True
                    fp_reason = f"AI analysis indicates '{keyword}'"
                    break
            
            # Check 3: Evidence contains placeholder patterns
            evidence_text = (result.evidence or "").upper()
            for pattern in placeholder_patterns:
                if re.search(pattern, evidence_text, re.IGNORECASE):
                    is_false_positive = True
                    fp_reason = f"Evidence contains placeholder pattern"
                    break
            
            # Check 4: Missing header findings with no actual security impact
            if result.vulnerability_type in [VulnerabilityType.SECURITY_MISCONFIGURATION]:
                # These are valid LOW findings, not false positives
                # Just ensure they're properly classified
                if result.severity in [Severity.HIGH, Severity.CRITICAL]:
                    result.severity = Severity.LOW
                    result.ai_analysis += "\n\n[Calibration] Security configuration findings are LOW severity unless proven exploitable."
            
            if is_false_positive:
                print(f"[Orchestrator] Filtered false positive: '{result.title}' - {fp_reason}")
                # Instead of removing, mark as INFO with explanation
                result.severity = Severity.INFO
                result.confidence = min(result.confidence, 25)
                result.ai_analysis += f"\n\n[False Positive Filter] This finding was flagged as potential false positive: {fp_reason}. Manual verification recommended."
            
            filtered_results.append(result)
        
        return filtered_results
    
    def _apply_exploitability_gates(self, results: List[AgentResult]) -> List[AgentResult]:
        """
        Apply exploitability gates to HIGH/CRITICAL findings.
        
        Gates:
        1. Is user interaction required?
        2. Is authentication required?
        3. Is sensitive data involved?
        4. Is impact cross-user (affects other users)?
        
        If ≥2 gates evaluate to "reduces exploitability" → downgrade severity.
        
        Args:
            results: List of findings
            
        Returns:
            Results with gated severities
        """
        for result in results:
            if result.severity not in [Severity.HIGH, Severity.CRITICAL]:
                continue
            
            gates_failed = 0
            gate_details = []
            
            # Gate 1: User Interaction Required
            # XSS, Clickjacking, CSRF require user interaction
            user_interaction_vulns = [
                VulnerabilityType.XSS_REFLECTED,
                VulnerabilityType.XSS_STORED,
                VulnerabilityType.XSS_DOM,
                VulnerabilityType.CSRF
            ]
            if result.vulnerability_type in user_interaction_vulns:
                gates_failed += 1
                gate_details.append("requires user interaction")
            
            # Gate 2: Authentication Required for Exploitation
            # Check if the finding mentions auth requirement
            auth_keywords = ["authenticated", "logged in", "session required", "auth required"]
            requires_auth = any(kw in result.description.lower() or kw in result.exploitability_rationale.lower() 
                               for kw in auth_keywords)
            if requires_auth:
                gates_failed += 1
                gate_details.append("requires authentication")
            
            # Gate 3: Sensitive Data Involvement
            # If no sensitive data is mentioned, it's less critical
            sensitive_keywords = ["password", "credit card", "ssn", "token", "secret", "api_key", "session", "pii"]
            involves_sensitive = any(
                kw in result.description.lower() or 
                kw in result.evidence.lower() or
                kw in result.title.lower()
                for kw in sensitive_keywords
            )
            if not involves_sensitive:
                gates_failed += 1
                gate_details.append("no sensitive data directly involved")
            
            # Gate 4: Cross-User Impact
            # Stored XSS, IDOR affecting other users = cross-user
            cross_user_vulns = [VulnerabilityType.XSS_STORED, VulnerabilityType.IDOR]
            is_cross_user = result.vulnerability_type in cross_user_vulns
            if not is_cross_user:
                gates_failed += 1
                gate_details.append("impact limited to single user/session")
            
            # Apply downgrade if ≥2 gates failed
            if gates_failed >= 2:
                original_severity = result.severity
                
                if result.severity == Severity.CRITICAL:
                    result.severity = Severity.HIGH
                elif result.severity == Severity.HIGH:
                    result.severity = Severity.MEDIUM
                
                result.ai_analysis += f"\n\n[Exploitability Gate] Severity adjusted from {original_severity.value} to {result.severity.value}. Factors: {', '.join(gate_details)}."
                result.confidence = max(result.confidence - 10, 50)
                print(f"[Orchestrator] Gated '{result.title}': {original_severity.value} → {result.severity.value} ({gates_failed} gates failed)")
        
        return results
    
    def _calculate_scan_metrics(self) -> None:
        """
        Calculate scan quality metrics for internal tracking.
        
        Metrics tracked:
        - findings_count: Total findings
        - severity_distribution: Breakdown by severity
        - evidence_completeness: % of findings with evidence
        - chained_ratio: % of findings that were correlated/chained
        - confidence_avg: Average confidence score
        - endpoints_tested: Number of unique endpoints
        """
        if not self.results:
            self.scan_metrics = {"findings_count": 0}
            return
        
        # Basic counts
        findings_count = len(self.results)
        
        # Severity distribution
        severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in self.results:
            severity_dist[r.severity.value] = severity_dist.get(r.severity.value, 0) + 1
        
        # Evidence completeness
        with_evidence = sum(1 for r in self.results if r.evidence and len(r.evidence.strip()) > 10)
        evidence_completeness = (with_evidence / findings_count * 100) if findings_count > 0 else 0
        
        # Chained/correlated findings (check for [Correlation] marker)
        chained_count = sum(1 for r in self.results if "[Correlation]" in r.ai_analysis)
        chained_ratio = (chained_count / findings_count * 100) if findings_count > 0 else 0
        
        # Average confidence
        confidence_avg = sum(r.confidence for r in self.results) / findings_count if findings_count > 0 else 0
        
        # Unique endpoints
        unique_endpoints = len(set(r.url for r in self.results))
        
        # Findings per endpoint (noise indicator - lower is better for signal quality)
        findings_per_endpoint = findings_count / unique_endpoints if unique_endpoints > 0 else 0
        
        # Gated findings (check for [Exploitability Gate] marker)
        gated_count = sum(1 for r in self.results if "[Exploitability Gate]" in r.ai_analysis)
        
        # Evidence-downgraded findings
        evidence_downgraded = sum(1 for r in self.results if "[Evidence Gate]" in r.ai_analysis)
        
        self.scan_metrics = {
            "findings_count": findings_count,
            "severity_distribution": severity_dist,
            "evidence_completeness_pct": round(evidence_completeness, 1),
            "chained_findings_ratio_pct": round(chained_ratio, 1),
            "average_confidence": round(confidence_avg, 1),
            "unique_endpoints_tested": unique_endpoints,
            "findings_per_endpoint": round(findings_per_endpoint, 2),
            "exploitability_gated_count": gated_count,
            "evidence_downgraded_count": evidence_downgraded,
            "signal_quality_score": self._calculate_signal_quality_score(
                evidence_completeness, chained_ratio, findings_per_endpoint, confidence_avg
            )
        }
        
        print(f"[Orchestrator] Scan Metrics: {self.scan_metrics}")
    
    def _calculate_signal_quality_score(
        self, 
        evidence_pct: float, 
        chained_pct: float, 
        findings_per_ep: float,
        avg_confidence: float
    ) -> float:
        """
        Calculate overall signal quality score (0-100).
        
        Higher = better quality findings (less noise, more intelligence).
        
        Components:
        - Evidence completeness (30%): More evidence = higher quality
        - Chained findings ratio (25%): More correlation = more intelligence
        - Findings per endpoint (25%): Lower = less noise (inverse scoring)
        - Average confidence (20%): Higher confidence = better
        """
        # Evidence score (0-30)
        evidence_score = (evidence_pct / 100) * 30
        
        # Chained score (0-25) - reward correlation
        chained_score = min((chained_pct / 50) * 25, 25)  # Cap at 50% chained = max score
        
        # Noise score (0-25) - penalize too many findings per endpoint
        # 1 finding per endpoint = 25, 5+ findings = 0
        if findings_per_ep <= 1:
            noise_score = 25
        elif findings_per_ep >= 5:
            noise_score = 0
        else:
            noise_score = 25 - ((findings_per_ep - 1) / 4) * 25
        
        # Confidence score (0-20)
        confidence_score = (avg_confidence / 100) * 20
        
        total = evidence_score + chained_score + noise_score + confidence_score
        return round(total, 1)


# Singleton orchestrator instance
orchestrator = AgentOrchestrator()
