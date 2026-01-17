"""
Agent Orchestrator - Coordinates multiple security agents for comprehensive scanning.

This module provides the orchestration layer for managing and coordinating
multiple security scanning agents with dependency resolution, retry logic,
and intelligent result correlation.
"""
import asyncio
import logging
import re
from typing import List, Dict, Any, Optional, Set, Callable, TypedDict
from datetime import datetime, timezone
from enum import Enum
from difflib import SequenceMatcher
from dataclasses import dataclass, field

from .base_agent import BaseSecurityAgent, AgentResult
from .github_agent import GithubSecurityAgent
from models.scan import Scan, ScanStatus
from models.vulnerability import Vulnerability, Severity, VulnerabilityType
from core.scan_context import ScanContext, AgentPhase

# Configure logging
logger = logging.getLogger(__name__)


# ==================== Type Definitions ====================

class EndpointDict(TypedDict, total=False):
    """Type definition for endpoint dictionaries."""
    url: str
    method: str
    params: Dict[str, Any]


# ==================== Constants ====================

class AgentNames:
    """Agent name constants for dependency management."""
    GITHUB = "github_security"
    AUTH = "authentication"
    API = "api_security"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"
    SECURITY_HEADERS = "security_headers"
    COMMAND_INJECTION = "command_injection"


class OrchestratorConfig:
    """Configuration constants for orchestrator behavior."""

    # Timeouts (seconds)
    DEFAULT_AGENT_TIMEOUT = 300
    GITHUB_AGENT_TIMEOUT = 600
    EXPLOITATION_AGENT_TIMEOUT = 600
    DISCOVERY_AGENT_TIMEOUT = 300

    # Retry configuration
    DEFAULT_MAX_RETRIES = 2
    RETRY_BACKOFF_BASE = 2
    RETRY_MAX_WAIT = 10

    # Similarity thresholds
    SIMILARITY_THRESHOLD = 0.85
    MIN_EVIDENCE_LENGTH = 10

    # Confidence adjustments
    CONFIDENCE_BOOST_CORRELATION = 10
    CONFIDENCE_BOOST_CSP_XSS = 10
    CONFIDENCE_BOOST_HSTS = 15
    CONFIDENCE_PENALTY_NO_EVIDENCE = 10
    CONFIDENCE_PENALTY_GATES = 10
    MIN_CONFIDENCE_THRESHOLD = 30

    # Progress percentages
    PROGRESS_DISCOVERY_START = 5
    PROGRESS_DISCOVERY_COMPLETE = 15
    PROGRESS_SCANNING_START = 15
    PROGRESS_SCANNING_END = 85
    PROGRESS_ANALYSIS_START = 85
    PROGRESS_DEDUPLICATION = 92
    PROGRESS_COMPLETE = 100

    # Exploitability gates
    GATES_REQUIRED_FOR_DOWNGRADE = 2

    # Quality metrics
    MAX_CHAINED_RATIO_FOR_SCORE = 50
    MAX_FINDINGS_PER_ENDPOINT = 5

    # WAF Evasion settings
    WAF_EVASION_ENABLED = True
    MAX_EVASION_ATTEMPTS = 30
    EVASION_DELAY_SECONDS = 0.3
    AUTO_WAF_DETECTION = True


class PatternConstants:
    """Regex patterns for endpoint routing and filtering."""

    AUTH_PATTERNS = [
        r'/login', r'/signin', r'/sign-in',
        r'/auth', r'/register', r'/signup'
    ]

    API_PATTERNS = [
        r'/api/', r'/v\d+/', r'\.json',
        r'/rest/', r'/graphql'
    ]

    SSRF_PATTERNS = [
        r'url', r'link', r'src', r'href',
        r'path', r'file', r'fetch', r'redirect',
        r'callback', r'proxy'
    ]

    CMD_PATTERNS = [
        r'cmd', r'exec', r'command', r'run',
        r'ping', r'host', r'ip', r'file', r'path'
    ]

    PLACEHOLDER_PATTERNS = [
        r"YOUR_.*_HERE", r"EXAMPLE_.*", r"\*\*\*\*",
        r"xxxx", r"<YOUR.*>", r"\[INSERT.*\]"
    ]


class FalsePositiveIndicators:
    """Keywords indicating false positives."""

    KEYWORDS = [
        "not vulnerable", "false positive", "placeholder",
        "example value", "your_api_key_here", "xxx-xxx",
        "not exploitable", "properly encoded",
        "correctly sanitized", "no sensitive data is present"
    ]


class SensitiveDataKeywords:
    """Keywords indicating sensitive data involvement."""

    KEYWORDS = [
        "password", "credit card", "ssn", "token",
        "secret", "api_key", "session", "pii"
    ]


# ==================== Custom Exceptions ====================

class OrchestratorError(Exception):
    """Base exception for orchestrator errors."""
    pass


class AgentRegistrationError(OrchestratorError):
    """Raised when agent registration fails."""
    pass


class CircularDependencyError(OrchestratorError):
    """Raised when circular dependencies are detected."""
    pass


class AgentExecutionError(OrchestratorError):
    """Raised when agent execution fails."""
    pass


class EndpointDiscoveryError(OrchestratorError):
    """Raised when endpoint discovery fails."""
    pass


# ==================== Data Classes ====================

@dataclass
class AgentNode:
    """Node in the agent dependency graph."""
    agent: BaseSecurityAgent
    phase: AgentPhase
    dependencies: List[str] = field(default_factory=list)
    timeout_seconds: int = OrchestratorConfig.DEFAULT_AGENT_TIMEOUT
    max_retries: int = OrchestratorConfig.DEFAULT_MAX_RETRIES

    def has_dependencies_satisfied(self, completed: Set[str], scan_scope: Set[str]) -> bool:
        """
        Check if all dependencies are satisfied.
        Only considers dependencies that are part of the current scan scope.
        """
        return all(
            dep in completed 
            for dep in self.dependencies 
            if dep in scan_scope
        )


@dataclass
class ScanMetrics:
    """Metrics for scan quality assessment."""
    findings_count: int = 0
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    evidence_completeness_pct: float = 0.0
    chained_findings_ratio_pct: float = 0.0
    average_confidence: float = 0.0
    unique_endpoints_tested: int = 0
    findings_per_endpoint: float = 0.0
    exploitability_gated_count: int = 0
    evidence_downgraded_count: int = 0
    signal_quality_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "findings_count": self.findings_count,
            "severity_distribution": self.severity_distribution,
            "evidence_completeness_pct": round(self.evidence_completeness_pct, 1),
            "chained_findings_ratio_pct": round(self.chained_findings_ratio_pct, 1),
            "average_confidence": round(self.average_confidence, 1),
            "unique_endpoints_tested": self.unique_endpoints_tested,
            "findings_per_endpoint": round(self.findings_per_endpoint, 2),
            "exploitability_gated_count": self.exploitability_gated_count,
            "evidence_downgraded_count": self.evidence_downgraded_count,
            "signal_quality_score": round(self.signal_quality_score, 1)
        }


class ScanPhase(str, Enum):
    """Phases of the scanning process."""
    RECONNAISSANCE = "reconnaissance"
    ACTIVE_SCANNING = "active_scanning"
    ANALYSIS = "analysis"
    REPORTING = "reporting"


# ==================== Main Orchestrator Class ====================

class AgentOrchestrator:
    """
    Orchestrator that manages and coordinates multiple security agents.

    Responsibilities:
    - Agent lifecycle management
    - Dependency-based execution ordering
    - Result aggregation and correlation
    - Progress tracking and callbacks
    - Error handling and retries

    Example:
        >>> orchestrator = AgentOrchestrator()
        >>> results = await orchestrator.run_scan(
        ...     target_url="https://example.com",
        ...     agents_enabled=["sql_injection", "xss"]
        ... )
    """

    def __init__(self):
        """Initialize the orchestrator."""
        self.agents: Dict[str, BaseSecurityAgent] = {}
        self.agent_nodes: Dict[str, AgentNode] = {}
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
        self.on_progress: Optional[Callable] = None
        self.on_vulnerability_found: Optional[Callable] = None

        # Metrics
        self.scan_metrics: Optional[ScanMetrics] = None

        # Lazy loading: Agent registry (not initialized yet)
        self._agent_registry: Dict[str, Dict[str, Any]] = {}
        self._loaded_agents: Set[str] = set()
        self._build_agent_registry()

    # ==================== Agent Registration ====================

    def _build_agent_registry(self) -> None:
        """Build agent registry for lazy loading (no initialization yet)."""
        # Registry maps agent_name -> {class, phase, dependencies, timeout}
        self._agent_registry = {
            AgentNames.GITHUB: {
                "class": "GithubSecurityAgent",
                "module": ".github_agent",
                "phase": AgentPhase.RECONNAISSANCE,
                "dependencies": [],
                "timeout": OrchestratorConfig.GITHUB_AGENT_TIMEOUT,
                "requires_config": True  # Needs GitHub token
            },
            AgentNames.AUTH: {
                "class": "AuthenticationAgent",
                "module": ".auth_agent",
                "phase": AgentPhase.DISCOVERY,
                "dependencies": [AgentNames.GITHUB],
                "timeout": OrchestratorConfig.DISCOVERY_AGENT_TIMEOUT
            },
            AgentNames.API: {
                "class": "APISecurityAgent",
                "module": ".api_security_agent",
                "phase": AgentPhase.DISCOVERY,
                "dependencies": [AgentNames.GITHUB],
                "timeout": OrchestratorConfig.DISCOVERY_AGENT_TIMEOUT
            },
            AgentNames.SQL_INJECTION: {
                "class": "SQLInjectionAgent",
                "module": ".sql_injection_agent",
                "phase": AgentPhase.EXPLOITATION,
                "dependencies": [AgentNames.AUTH, AgentNames.API],
                "timeout": OrchestratorConfig.EXPLOITATION_AGENT_TIMEOUT
            },
            AgentNames.XSS: {
                "class": "XSSAgent",
                "module": ".xss_agent",
                "phase": AgentPhase.EXPLOITATION,
                "dependencies": [AgentNames.AUTH, AgentNames.API],
                "timeout": OrchestratorConfig.EXPLOITATION_AGENT_TIMEOUT
            },
            AgentNames.CSRF: {
                "class": "CSRFAgent",
                "module": ".csrf_agent",
                "phase": AgentPhase.EXPLOITATION,
                "dependencies": [AgentNames.AUTH],
                "timeout": OrchestratorConfig.DISCOVERY_AGENT_TIMEOUT
            },
            AgentNames.SSRF: {
                "class": "SSRFAgent",
                "module": ".ssrf_agent",
                "phase": AgentPhase.EXPLOITATION,
                "dependencies": [AgentNames.API],
                "timeout": OrchestratorConfig.DISCOVERY_AGENT_TIMEOUT
            },
            AgentNames.COMMAND_INJECTION: {
                "class": "CommandInjectionAgent",
                "module": ".command_injection_agent",
                "phase": AgentPhase.EXPLOITATION,
                "dependencies": [AgentNames.API],
                "timeout": OrchestratorConfig.DISCOVERY_AGENT_TIMEOUT
            }
        }

    def _load_agent_on_demand(self, agent_name: str) -> BaseSecurityAgent:
        """Lazy load an agent when needed."""
        if agent_name in self.agents:
            return self.agents[agent_name]

        if agent_name not in self._agent_registry:
            raise AgentRegistrationError(f"Unknown agent: {agent_name}")

        config = self._agent_registry[agent_name]
        
        try:
            # Import the agent module
            import importlib
            module = importlib.import_module(config["module"], package="agents")
            agent_class = getattr(module, config["class"])

            # Initialize agent
            if config.get("requires_config"):
                # GitHub agent needs token
                from config import get_settings
                settings = get_settings()
                agent = agent_class(github_token=settings.github_token)
            else:
                agent = agent_class()

            # Register it
            self.register_agent(
                agent,
                phase=config["phase"],
                dependencies=config["dependencies"],
                timeout_seconds=config["timeout"]
            )

            self._loaded_agents.add(agent_name)
            logger.info(f"Lazy loaded agent: {agent_name}")

            return agent

        except Exception as e:
            logger.error(f"Failed to load agent {agent_name}: {e}")
            raise AgentRegistrationError(f"Agent load failed: {agent_name} - {e}")

    def _unload_agent(self, agent_name: str) -> None:
        """Unload an agent to free memory."""
        if agent_name not in self.agents:
            return

        agent = self.agents[agent_name]
        
        try:
            # Close HTTP sessions if agent has them
            if hasattr(agent, 'close'):
                if asyncio.iscoroutinefunction(agent.close):
                    # Can't await here, so we'll just mark for cleanup
                    logger.debug(f"Agent {agent_name} has async close, scheduling")
                else:
                    agent.close()

            # Remove from registry
            del self.agents[agent_name]
            if agent_name in self.agent_nodes:
                del self.agent_nodes[agent_name]
            
            self._loaded_agents.discard(agent_name)

            # Force garbage collection
            import gc
            gc.collect()

            logger.info(f"Unloaded agent: {agent_name}")

        except Exception as e:
            logger.error(f"Error unloading agent {agent_name}: {e}")

    def _register_agent_safe(
            self,
            agent: BaseSecurityAgent,
            phase: AgentPhase,
            dependencies: List[str],
            timeout_seconds: int
    ) -> None:
        """
        Safely register an agent with error handling.

        Args:
            agent: Agent instance to register
            phase: Execution phase
            dependencies: List of agent name dependencies
            timeout_seconds: Execution timeout

        Raises:
            AgentRegistrationError: If registration fails
        """
        try:
            self.register_agent(agent, phase, dependencies, timeout_seconds)
        except Exception as e:
            logger.error(f"Failed to register agent {agent.agent_name}: {e}")
            # Continue with other agents

    def register_agent(
            self,
            agent: BaseSecurityAgent,
            phase: AgentPhase = AgentPhase.EXPLOITATION,
            dependencies: Optional[List[str]] = None,
            timeout_seconds: int = OrchestratorConfig.DEFAULT_AGENT_TIMEOUT
    ) -> None:
        """
        Register a security agent with the orchestrator.

        Args:
            agent: Security agent instance to register
            phase: Execution phase for this agent
            dependencies: List of agent names this agent depends on
            timeout_seconds: Max execution time for this agent

        Raises:
            AgentRegistrationError: If agent is invalid or already registered
        """
        if not isinstance(agent, BaseSecurityAgent):
            raise AgentRegistrationError(
                f"Agent must be instance of BaseSecurityAgent, got {type(agent)}"
            )

        if agent.agent_name in self.agents:
            logger.warning(f"Agent {agent.agent_name} already registered, skipping")
            return

        self.agents[agent.agent_name] = agent
        self.agent_nodes[agent.agent_name] = AgentNode(
            agent=agent,
            phase=phase,
            dependencies=dependencies or [],
            timeout_seconds=timeout_seconds
        )

        logger.info(f"Registered agent: {agent.agent_name} (phase: {phase.value})")

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
            logger.info(f"Unregistered agent: {agent_name}")
        else:
            logger.warning(f"Attempted to unregister unknown agent: {agent_name}")

    # ==================== Main Scan Execution ====================

    async def run_scan(
            self,
            target_url: str,
            agents_enabled: Optional[List[str]] = None,
            endpoints: Optional[List[EndpointDict]] = None,
            technology_stack: Optional[List[str]] = None,
            scan_id: int = 0
    ) -> List[AgentResult]:
        """
        Execute a comprehensive security scan using dependency graph.

        Args:
            target_url: Base URL of the target
            agents_enabled: List of agent names to use (None = auto-select)
            endpoints: List of endpoints to test
            technology_stack: Detected technologies
            scan_id: ID of the scan in database

        Returns:
            List of all vulnerabilities found

        Raises:
            OrchestratorError: If scan fails
        """
        # Validate input
        if not target_url:
            raise ValueError("target_url cannot be empty")

        # Initialize scan state
        self._initialize_scan_state()
        target_url = self._normalize_url(target_url)

        logger.info(f"Starting scan of {target_url}")
        logger.info(f"Enabled agents: {agents_enabled or 'all (auto-selected)'}")

        try:
            # Initialize scan context
            self.scan_context = ScanContext(
                scan_id=scan_id,
                target_url=target_url,
                technology_stack=technology_stack or []
            )

            # Phase 1: Reconnaissance
            await self._execute_reconnaissance_phase(
                target_url, endpoints, technology_stack
            )

            # Phase 2: Active Scanning
            await self._execute_scanning_phase(
                target_url, agents_enabled
            )

            # Phase 3: Analysis (Intelligence Layer)
            await self._execute_analysis_phase()

            # Phase 4: Reporting
            await self._execute_reporting_phase()

            logger.info(
                f"Scan complete. Found {len(self.results)} vulnerabilities"
            )

            if self.failed_agents:
                failed_names = [a['agent'] for a in self.failed_agents]
                logger.warning(
                    f"{len(self.failed_agents)} agents failed: {failed_names}"
                )

            return self.results

        except Exception as e:
            logger.error(f"Scan error: {e}", exc_info=True)
            raise OrchestratorError(f"Scan failed: {e}")
        finally:
            self.is_running = False

    def _initialize_scan_state(self) -> None:
        """Initialize state for a new scan."""
        self.is_running = True
        self.should_cancel = False
        self.results = []
        self.progress = 0
        self.failed_agents = []
        self.current_phase = ScanPhase.RECONNAISSANCE

    def _normalize_url(self, url: str) -> str:
        """Ensure URL has proper scheme."""
        if not url.startswith(("http://", "https://")):
            return f"http://{url}"
        return url

    # ==================== Scan Phases ====================

    async def _execute_reconnaissance_phase(
            self,
            target_url: str,
            endpoints: Optional[List[EndpointDict]],
            technology_stack: Optional[List[str]]
    ) -> None:
        """Execute reconnaissance phase."""
        self.current_phase = ScanPhase.RECONNAISSANCE
        await self._update_progress(
            OrchestratorConfig.PROGRESS_DISCOVERY_START,
            "Analyzing target..."
        )

        # Discover endpoints if not provided - with global timeout to prevent hangs
        if endpoints is None:
            try:
                endpoints = await asyncio.wait_for(
                    self._discover_endpoints(target_url),
                    timeout=120.0
                )
            except asyncio.TimeoutError:
                logger.warning(f"Reconnaissance timed out for {target_url} after 120s. Using fallback.")
                endpoints = [{"url": target_url, "method": "GET", "params": {}}]

        self.scan_context.discovered_endpoints = endpoints

        logger.info(f"Target: {target_url}")
        logger.info(f"Discovered endpoints: {len(endpoints)}")

        # Detect technology if not provided
        if technology_stack is None:
            technology_stack = await self._detect_technology(target_url)

        self.scan_context.technology_stack = technology_stack

        await self._update_progress(
            OrchestratorConfig.PROGRESS_DISCOVERY_COMPLETE,
            "Discovery complete"
        )

    async def _execute_scanning_phase(
            self,
            target_url: str,
            agents_enabled: Optional[List[str]]
    ) -> None:
        """Execute active scanning phase."""
        self.current_phase = ScanPhase.ACTIVE_SCANNING

        # Select agents to run
        agents_to_run = self._select_agents(target_url, agents_enabled)

        logger.info(f"Agents to run: {agents_to_run}")

        if not agents_to_run:
            logger.warning("No agents enabled!")
            return

        # Execute agents in dependency order
        agent_results = await self._execute_agents_graph(
            agents_to_run,
            target_url,
            self.scan_context.discovered_endpoints,
            self.scan_context.technology_stack
        )

        # Collect results
        for result in agent_results:
            if isinstance(result, list):
                self.results.extend(result)

    async def _execute_analysis_phase(self) -> None:
        """Execute analysis phase with intelligence layer."""
        self.current_phase = ScanPhase.ANALYSIS
        await self._update_progress(
            OrchestratorConfig.PROGRESS_ANALYSIS_START,
            "Applying intelligence layer..."
        )

        # Apply intelligence transformations in order
        self.results = self._validate_evidence(self.results)
        self.results = self._filter_false_positives(self.results)
        self.results = self._correlate_results(self.results)
        self.results = self._apply_exploitability_gates(self.results)
        self.results = self._calculate_verdicts(self.results)
        self.results = self._calculate_scope_impact(self.results)

        # Deduplicate and sort
        await self._update_progress(
            OrchestratorConfig.PROGRESS_DEDUPLICATION,
            "Deduplicating results..."
        )

        self.results = self._deduplicate_results_similarity(self.results)
        self.results = self._sort_results(self.results)

    async def _execute_reporting_phase(self) -> None:
        """Execute reporting phase."""
        self.current_phase = ScanPhase.REPORTING

        # Calculate metrics
        self._calculate_scan_metrics()

        await self._update_progress(
            OrchestratorConfig.PROGRESS_COMPLETE,
            "Scan complete"
        )

    # ==================== Agent Selection and Routing ====================

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

        # Auto-select based on target type
        if is_github_target:
            logger.info("GitHub target detected - forcing GitHub Security Agent only")
            return [AgentNames.GITHUB] if AgentNames.GITHUB in self._agent_registry else []
        
        if agents_enabled is not None:
            # Use explicitly enabled agents (check registry, not loaded agents)
            return [name for name in agents_enabled if name in self._agent_registry]

        # Default for web targets: Run all non-GitHub agents from registry
        return [
            name for name in self._agent_registry.keys()
            if name != AgentNames.GITHUB
        ]

    def _route_endpoints_for_agent(
            self,
            agent_name: str,
            all_endpoints: List[EndpointDict]
    ) -> List[EndpointDict]:
        """
        Filter endpoints relevant for a specific agent.

        Args:
            agent_name: Name of the agent
            all_endpoints: All discovered endpoints

        Returns:
            Filtered list of relevant endpoints
        """
        # Define routing logic for each agent type
        routing_map = {
            AgentNames.AUTH: self._route_auth_endpoints,
            AgentNames.API: self._route_api_endpoints,
            AgentNames.SQL_INJECTION: self._route_sqli_endpoints,
            AgentNames.XSS: self._route_xss_endpoints,
            AgentNames.CSRF: self._route_csrf_endpoints,
            AgentNames.SSRF: self._route_ssrf_endpoints,
            AgentNames.COMMAND_INJECTION: self._route_cmd_endpoints,
            AgentNames.GITHUB: lambda eps: eps,  # Pass all for GitHub
        }

        router = routing_map.get(agent_name)
        if router:
            return router(all_endpoints)

        # Default: return all endpoints
        return all_endpoints

    def _route_auth_endpoints(
            self, endpoints: List[EndpointDict]
    ) -> List[EndpointDict]:
        """Route authentication-related endpoints."""
        filtered = [
            ep for ep in endpoints
            if any(
                re.search(pattern, ep.get("url", ""), re.IGNORECASE)
                for pattern in PatternConstants.AUTH_PATTERNS
            )
        ]

        # Fallback: return login endpoint if available
        if not filtered:
            filtered = [
                ep for ep in endpoints
                if "/login" in ep.get("url", "").lower()
            ]

        return filtered if filtered else endpoints[:1]  # At least one endpoint

    def _route_api_endpoints(
            self, endpoints: List[EndpointDict]
    ) -> List[EndpointDict]:
        """Route API endpoints."""
        return [
            ep for ep in endpoints
            if any(
                re.search(pattern, ep.get("url", ""), re.IGNORECASE)
                for pattern in PatternConstants.API_PATTERNS
            )
        ]

    def _route_sqli_endpoints(
            self, endpoints: List[EndpointDict]
    ) -> List[EndpointDict]:
        """Route SQL injection test endpoints."""
        return [
            ep for ep in endpoints
            if ep.get("params") or
               "?" in ep.get("url", "") or
               ep.get("method") == "POST"
        ]

    def _route_xss_endpoints(
            self, endpoints: List[EndpointDict]
    ) -> List[EndpointDict]:
        """Route XSS test endpoints."""
        return [
            ep for ep in endpoints
            if ep.get("params") or
               "search" in ep.get("url", "").lower() or
               "q=" in ep.get("url", "")
        ]

    def _route_csrf_endpoints(
            self, endpoints: List[EndpointDict]
    ) -> List[EndpointDict]:
        """Route CSRF test endpoints."""
        state_changing_methods = {"POST", "PUT", "DELETE", "PATCH"}
        state_changing_paths = ["/update", "/delete", "/create", "/edit", "/submit"]

        return [
            ep for ep in endpoints
            if ep.get("method", "GET").upper() in state_changing_methods or
               any(p in ep.get("url", "").lower() for p in state_changing_paths)
        ]

    def _route_ssrf_endpoints(
            self, endpoints: List[EndpointDict]
    ) -> List[EndpointDict]:
        """Route SSRF test endpoints."""
        return [
            ep for ep in endpoints
            if any(
                any(
                    re.search(pattern, str(p), re.IGNORECASE)
                    for pattern in PatternConstants.SSRF_PATTERNS
                )
                for p in ep.get("params", {}).keys()
            ) or any(
                re.search(pattern, ep.get("url", ""), re.IGNORECASE)
                for pattern in PatternConstants.SSRF_PATTERNS
            )
        ]

    def _route_cmd_endpoints(
            self, endpoints: List[EndpointDict]
    ) -> List[EndpointDict]:
        """Route command injection test endpoints."""
        return [
            ep for ep in endpoints
            if any(
                any(
                    re.search(pattern, str(p), re.IGNORECASE)
                    for pattern in PatternConstants.CMD_PATTERNS
                )
                for p in ep.get("params", {}).keys()
            ) or ep.get("params")
        ]

    # ==================== Agent Execution ====================

    async def _execute_agents_graph(
            self,
            agent_names: List[str],
            target_url: str,
            endpoints: List[EndpointDict],
            technology_stack: List[str]
    ) -> List[List[AgentResult]]:
        """
        Execute agents respecting dependency graph.

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
        phases = self._group_agents_by_phase(agent_names)

        # Execute phases sequentially
        phase_order = [
            AgentPhase.RECONNAISSANCE,
            AgentPhase.DISCOVERY,
            AgentPhase.EXPLOITATION,
            AgentPhase.ANALYSIS
        ]

        total_phases = sum(1 for p in phase_order if phases[p])
        current_phase_num = 0

        for phase in phase_order:
            phase_agents = phases[phase]
            if not phase_agents:
                continue

            current_phase_num += 1
            progress = self._calculate_phase_progress(
                current_phase_num, total_phases
            )

            logger.info(
                f"Executing {phase.value} phase with {len(phase_agents)} agents"
            )
            await self._update_progress(int(progress), f"Phase: {phase.value}")

            # Execute agents in this phase
            phase_results = await self._execute_phase_agents(
                phase_agents,
                target_url,
                endpoints,
                technology_stack,
                completed_agents,
                set(agent_names)
            )

            all_results.extend(phase_results)
            completed_agents.update(phase_agents)

            # MEMORY OPTIMIZATION: Unload agents from this phase
            for agent_name in phase_agents:
                self._unload_agent(agent_name)

            logger.info(f"Phase {phase.value} complete, agents unloaded")

        return all_results

    def _group_agents_by_phase(
            self, agent_names: List[str]
    ) -> Dict[AgentPhase, List[str]]:
        """Group agents by execution phase."""
        phases = {
            AgentPhase.RECONNAISSANCE: [],
            AgentPhase.DISCOVERY: [],
            AgentPhase.EXPLOITATION: [],
            AgentPhase.ANALYSIS: []
        }

        for agent_name in agent_names:
            # Check registry first (for lazy loading), then loaded nodes
            if agent_name in self._agent_registry:
                phase = self._agent_registry[agent_name]["phase"]
                phases[phase].append(agent_name)
            elif agent_name in self.agent_nodes:
                node = self.agent_nodes[agent_name]
                phases[node.phase].append(agent_name)

        return phases

    def _calculate_phase_progress(
            self, current_phase: int, total_phases: int
    ) -> float:
        """Calculate progress percentage for current phase."""
        phase_start = OrchestratorConfig.PROGRESS_SCANNING_START
        phase_range = (
                OrchestratorConfig.PROGRESS_SCANNING_END - phase_start
        )
        return phase_start + (current_phase / total_phases) * phase_range

    async def _execute_phase_agents(
            self,
            agent_names: List[str],
            target_url: str,
            endpoints: List[EndpointDict],
            technology_stack: List[str],
            completed_agents: Set[str],
            scan_scope: Set[str]
    ) -> List[List[AgentResult]]:
        """
        Execute agents in a phase, respecting dependencies.

        Args:
            agent_names: Agents to execute in this phase
            target_url: Target URL
            endpoints: Endpoints to test
            technology_stack: Technology stack
            completed_agents: Set of already completed agents
            scan_scope: Set of all agents included in this scan

        Returns:
            Results from all agents in this phase

        Raises:
            CircularDependencyError: If circular dependencies detected
        """
        results = []
        remaining = set(agent_names)
        iterations = 0
        max_iterations = len(agent_names) * 2  # Prevent infinite loops

        while remaining and iterations < max_iterations:
            iterations += 1

            # Find agents with satisfied dependencies
            ready_agents = self._get_ready_agents(remaining, completed_agents, scan_scope)

            if not ready_agents:
                # Circular dependency detected
                self._handle_circular_dependency(remaining, completed_agents, scan_scope)
                break

            # Execute ready agents concurrently
            batch_results = await self._execute_agent_batch(
                ready_agents,
                target_url,
                endpoints,
                technology_stack
            )

            results.extend(batch_results)
            completed_agents.update(ready_agents)
            remaining -= set(ready_agents)

        if iterations >= max_iterations:
            logger.error(f"Max iterations reached, remaining agents: {remaining}")

        return results

    def _get_ready_agents(
            self, remaining: Set[str], completed: Set[str], scan_scope: Set[str]
    ) -> List[str]:
        """Get agents whose dependencies are satisfied."""
        ready = []
        for agent_name in remaining:
            # Lazy load agent if not already loaded
            if agent_name not in self.agents:
                try:
                    self._load_agent_on_demand(agent_name)
                except AgentRegistrationError:
                    logger.error(f"Failed to load agent {agent_name}, skipping")
                    continue

            node = self.agent_nodes[agent_name]
            if node.has_dependencies_satisfied(completed, scan_scope):
                ready.append(agent_name)
        return ready

    def _handle_circular_dependency(
            self, remaining: Set[str], completed: Set[str], scan_scope: Set[str]
    ) -> None:
        """Handle circular dependency error."""
        dependency_info = []
        for agent_name in remaining:
            node = self.agent_nodes[agent_name]
            unsatisfied = [
                dep for dep in node.dependencies
                if dep not in completed and dep in scan_scope
            ]
            dependency_info.append(f"{agent_name} -> {unsatisfied}")

        error_msg = (
            f"Circular dependency detected. "
            f"Cannot proceed with agents: {remaining}. "
            f"Dependencies: {', '.join(dependency_info)}"
        )

        logger.error(error_msg)
        raise CircularDependencyError(error_msg)

    async def _execute_agent_batch(
            self,
            agent_names: List[str],
            target_url: str,
            endpoints: List[EndpointDict],
            technology_stack: List[str]
    ) -> List[List[AgentResult]]:
        """Execute a batch of agents concurrently."""
        tasks = []

        for agent_name in agent_names:
            # Ensure agent is loaded (should already be from _get_ready_agents)
            if agent_name not in self.agents:
                logger.warning(f"Agent {agent_name} not loaded, loading now")
                try:
                    self._load_agent_on_demand(agent_name)
                except AgentRegistrationError as e:
                    logger.error(f"Failed to load {agent_name}: {e}")
                    continue

            agent = self.agents[agent_name]
            node = self.agent_nodes[agent_name]

            # Route endpoints for this agent
            agent_endpoints = self._route_endpoints_for_agent(
                agent_name, endpoints
            )

            task = self._run_agent_with_retry(
                agent,
                target_url,
                agent_endpoints,
                technology_stack,
                timeout=node.timeout_seconds,
                max_retries=node.max_retries
            )
            tasks.append(task)

        # Execute all agents concurrently
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results and errors
        results = []
        for i, result in enumerate(batch_results):
            if isinstance(result, Exception):
                agent_name = agent_names[i]
                logger.error(f"Agent {agent_name} failed: {result}")
                self.failed_agents.append({
                    "agent": agent_name,
                    "error": str(result),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            elif isinstance(result, list):
                results.append(result)

        return results

    async def _run_agent_with_retry(
            self,
            agent: BaseSecurityAgent,
            target_url: str,
            endpoints: List[EndpointDict],
            technology_stack: List[str],
            timeout: int,
            max_retries: int
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

        Raises:
            AgentExecutionError: If all retries fail
        """
        retry_count = 0
        last_error = None

        while retry_count <= max_retries:
            try:
                logger.info(
                    f"Running {agent.agent_name} "
                    f"(attempt {retry_count + 1}/{max_retries + 1})"
                )

                # Run with timeout
                results = await asyncio.wait_for(
                    self._run_agent(
                        agent, target_url, endpoints, technology_stack
                    ),
                    timeout=timeout
                )

                return results

            except asyncio.TimeoutError:
                last_error = f"Timeout after {timeout}s"
                logger.warning(
                    f"{agent.agent_name} timed out after {timeout}s"
                )

            except Exception as e:
                last_error = str(e)
                logger.error(f"{agent.agent_name} error: {e}")

            # Retry logic
            retry_count += 1
            if retry_count <= max_retries:
                wait_time = min(
                    OrchestratorConfig.RETRY_BACKOFF_BASE ** retry_count,
                    OrchestratorConfig.RETRY_MAX_WAIT
                )
                logger.info(
                    f"Retrying {agent.agent_name} in {wait_time}s..."
                )
                await asyncio.sleep(wait_time)

        # All retries failed
        error_msg = (
            f"{agent.agent_name} failed after {max_retries + 1} attempts: "
            f"{last_error}"
        )
        raise AgentExecutionError(error_msg)

    async def _run_agent(
            self,
            agent: BaseSecurityAgent,
            target_url: str,
            endpoints: List[EndpointDict],
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
        logger.info(f"Executing {agent.agent_name}...")

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

        logger.info(f"{agent.agent_name} found {len(results)} issues")
        return results

    # ==================== Endpoint Discovery ====================

    async def _discover_endpoints(
            self, target_url: str
    ) -> List[EndpointDict]:
        """
        Discover endpoints on the target.

        Args:
            target_url: Base URL to scan

        Returns:
            List of discovered endpoints
        """
        # Special handling for GitHub URLs
        if "github.com" in target_url:
            return [{"url": target_url, "method": "GIT", "params": {}}]

        try:
            from scanner.target_analyzer import TargetAnalyzer

            analyzer = TargetAnalyzer(timeout=30.0, max_depth=2)
            analysis = await analyzer.analyze(target_url)
            await analyzer.close()

            # Convert to dict format
            endpoints = [ep.to_dict() for ep in analysis.endpoints]

            logger.info(f"Discovered {len(endpoints)} endpoints")

            # Ensure at least one endpoint
            if not endpoints:
                endpoints = [{"url": target_url, "method": "GET", "params": {}}]

            return endpoints

        except Exception as e:
            logger.error(f"Error discovering endpoints: {e}")
            # Fallback to basic endpoint
            return [{"url": target_url, "method": "GET", "params": {}}]

    async def _detect_technology(self, target_url: str) -> List[str]:
        """
        Detect technology stack of the target.

        Args:
            target_url: URL to analyze

        Returns:
            List of detected technologies
        """
        # Special handling for GitHub
        if "github.com" in target_url:
            return ["GitHub Repository", "Source Code"]

        # Placeholder for actual technology detection
        return ["Web Application", "Unknown Framework"]

    # ==================== Intelligence Layer ====================

    def _validate_evidence(
            self, results: List[AgentResult]
    ) -> List[AgentResult]:
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
            has_evidence = self._has_valid_evidence(result)

            if not has_evidence:
                original_severity = result.severity

                if result.severity in [Severity.CRITICAL, Severity.HIGH]:
                    result.severity = Severity.MEDIUM
                    result.confidence = min(
                        result.confidence,
                        60
                    )
                    result.ai_analysis += (
                        f"\n\n[Evidence Gate] Severity downgraded from "
                        f"{original_severity.value} to MEDIUM: Insufficient "
                        f"evidence provided. High-severity findings require "
                        f"concrete request/response evidence."
                    )
                    logger.info(
                        f"Downgraded '{result.title}' due to missing evidence"
                    )

                elif result.severity == Severity.MEDIUM:
                    result.severity = Severity.LOW
                    result.confidence = min(result.confidence, 50)
                    result.ai_analysis += (
                        "\n\n[Evidence Gate] Severity downgraded from MEDIUM "
                        "to LOW: No concrete evidence provided."
                    )

        return results

    def _has_valid_evidence(self, result: AgentResult) -> bool:
        """Check if result has valid evidence."""
        has_evidence = bool(
            result.evidence and
            len(result.evidence.strip()) > OrchestratorConfig.MIN_EVIDENCE_LENGTH and
            result.evidence.lower() not in ["none", "n/a", "not available"]
        )

        has_response = bool(
            result.response_snippet and
            len(result.response_snippet.strip()) > 0
        )

        return has_evidence or has_response

    def _filter_false_positives(
            self, results: List[AgentResult]
    ) -> List[AgentResult]:
        """
        Filter out or mark false positive findings.

        Args:
            results: List of findings

        Returns:
            Results with false positives marked
        """
        for result in results:
            is_false_positive, reason = self._check_false_positive(result)

            if is_false_positive:
                self._mark_as_false_positive(result, reason)
                logger.info(
                    f"Suppressed false positive: '{result.title}' - {reason}"
                )

        return results

    def _check_false_positive(
            self, result: AgentResult
    ) -> tuple[bool, Optional[str]]:
        """
        Check if result is a false positive.

        Returns:
            Tuple of (is_false_positive, reason)
        """
        # Check 1: Very low confidence
        if result.confidence < OrchestratorConfig.MIN_CONFIDENCE_THRESHOLD:
            return True, "Low confidence indicates insufficient evidence"

        # Check 2: False positive keywords in analysis
        analysis_lower = (result.ai_analysis or "").lower()
        for keyword in FalsePositiveIndicators.KEYWORDS:
            if keyword in analysis_lower:
                return True, f"AI Analysis confirms: {keyword}"

        # Check 3: Placeholder patterns
        evidence_text = (result.evidence or "").upper()
        for pattern in PatternConstants.PLACEHOLDER_PATTERNS:
            if re.search(pattern, evidence_text, re.IGNORECASE):
                return True, "Evidence contains placeholder patterns"

        # Check 4: Security Misconfig calibration
        if (result.vulnerability_type == VulnerabilityType.SECURITY_MISCONFIG and
                result.severity in [Severity.HIGH, Severity.CRITICAL]):
            result.severity = Severity.LOW
            result.ai_analysis += (
                "\n\n[Calibration] Security configuration findings are "
                "LOW severity (Best Practices) unless proven exploitable."
            )

        return False, None

    def _mark_as_false_positive(
            self, result: AgentResult, reason: str
    ) -> None:
        """Mark a result as false positive."""
        result.is_suppressed = True
        result.is_false_positive = True
        result.suppression_reason = reason
        result.final_verdict = "FALSE_POSITIVE"
        result.action_required = False
        result.severity = Severity.INFO
        result.exploit_confidence = 0.0

    def _correlate_results(
            self, results: List[AgentResult]
    ) -> List[AgentResult]:
        """
        Correlate and escalate vulnerabilities based on chaining.

        Args:
            results: List of findings

        Returns:
            Results with correlations applied
        """
        if not results:
            return results

        logger.info(f"Correlating {len(results)} findings...")

        # Categorize results
        by_type = self._categorize_by_type(results)
        by_url = self._categorize_by_url(results)

        # Apply correlation rules
        results = self._correlate_xss_csp(results, by_type, by_url)
        results = self._correlate_idor_sensitive(results, by_type)
        results = self._correlate_hsts_auth(results, by_type)

        return results

    def _categorize_by_type(
            self, results: List[AgentResult]
    ) -> Dict[VulnerabilityType, List[AgentResult]]:
        """Categorize results by vulnerability type."""
        by_type = {}
        for r in results:
            if r.vulnerability_type not in by_type:
                by_type[r.vulnerability_type] = []
            by_type[r.vulnerability_type].append(r)
        return by_type

    def _categorize_by_url(
            self, results: List[AgentResult]
    ) -> Dict[str, List[AgentResult]]:
        """Categorize results by URL."""
        by_url = {}
        for r in results:
            if r.url not in by_url:
                by_url[r.url] = []
            by_url[r.url].append(r)
        return by_url

    def _correlate_xss_csp(
            self,
            results: List[AgentResult],
            by_type: Dict[VulnerabilityType, List[AgentResult]],
            by_url: Dict[str, List[AgentResult]]
    ) -> List[AgentResult]:
        """Correlate XSS with missing CSP."""
        xss_types = [
            VulnerabilityType.XSS_REFLECTED,
            VulnerabilityType.XSS_STORED,
            VulnerabilityType.XSS_DOM
        ]

        for xss_type in xss_types:
            if xss_type not in by_type:
                continue

            for xss in by_type[xss_type]:
                url_findings = by_url.get(xss.url, [])
                has_no_csp = any(
                    r.vulnerability_type == VulnerabilityType.SECURITY_MISCONFIG and
                    "Content-Security-Policy" in r.title
                    for r in url_findings
                )

                if has_no_csp:
                    logger.info(f"Escalating {xss.title} due to missing CSP")
                    xss.severity = (
                        Severity.HIGH
                        if xss.severity == Severity.MEDIUM
                        else xss.severity
                    )
                    xss.confidence = min(
                        100,
                        xss.confidence + OrchestratorConfig.CONFIDENCE_BOOST_CSP_XSS
                    )
                    xss.ai_analysis += (
                        "\n\n[Correlation] Severity escalated (confidence: high): "
                        "Missing Content-Security-Policy (CSP) significantly "
                        "increases the exploitability and impact of this XSS "
                        "vulnerability. Attackers can execute arbitrary "
                        "JavaScript without CSP restrictions."
                    )
                    xss.exploitability_rationale = (
                        "Directly exploitable. The absence of CSP allows "
                        "unhindered execution of malicious scripts in the "
                        "victim's browser context."
                    )

        return results

    def _correlate_idor_sensitive(
            self,
            results: List[AgentResult],
            by_type: Dict[VulnerabilityType, List[AgentResult]]
    ) -> List[AgentResult]:
        """Correlate IDOR with sensitive data exposure."""
        if (VulnerabilityType.IDOR not in by_type or
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE not in by_type):
            return results

        for idor in by_type[VulnerabilityType.IDOR]:
            for sensitive in by_type[VulnerabilityType.SENSITIVE_DATA_EXPOSURE]:
                if idor.url == sensitive.url:
                    logger.info(
                        "Escalating IDOR due to sensitive data exposure"
                    )
                    idor.severity = Severity.CRITICAL
                    idor.confidence = 100
                    idor.impact = 10.0
                    idor.likelihood = 9.0
                    idor.ai_analysis += (
                        f"\n\n[Correlation] Severity escalated (confidence: high): "
                        f"IDOR on this endpoint leads to direct exposure of "
                        f"sensitive data ({sensitive.title}). This chain "
                        f"represents a critical data breach risk."
                    )

        return results

    def _correlate_hsts_auth(
            self,
            results: List[AgentResult],
            by_type: Dict[VulnerabilityType, List[AgentResult]]
    ) -> List[AgentResult]:
        """Correlate missing HSTS with auth/session issues."""
        if VulnerabilityType.SECURITY_MISCONFIG not in by_type:
            return results

        hsts_missing = [
            r for r in by_type[VulnerabilityType.SECURITY_MISCONFIG]
            if "Strict-Transport-Security" in r.title or "HSTS" in r.title
        ]

        auth_issues = by_type.get(VulnerabilityType.BROKEN_AUTH, [])
        sensitive_data = by_type.get(VulnerabilityType.SENSITIVE_DATA_EXPOSURE, [])

        for hsts in hsts_missing:
            related_auth = [a for a in auth_issues if a.url == hsts.url]
            related_sensitive = [s for s in sensitive_data if s.url == hsts.url]

            if related_auth or related_sensitive:
                logger.info(
                    "Escalating missing HSTS due to session/sensitive data"
                )
                hsts.severity = Severity.MEDIUM
                hsts.confidence = min(
                    95,
                    hsts.confidence + OrchestratorConfig.CONFIDENCE_BOOST_HSTS
                )
                hsts.impact = max(hsts.impact, 6.0)
                hsts.likelihood = max(hsts.likelihood, 5.0)

                correlation_targets = (
                        [a.title for a in related_auth] +
                        [s.title for s in related_sensitive]
                )
                hsts.ai_analysis += (
                    f"\n\n[Correlation] Severity escalated (confidence: medium): "
                    f"Missing HSTS combined with {', '.join(correlation_targets[:2])} "
                    f"creates a session hijacking risk vector via MITM attacks "
                    f"on HTTP downgrade."
                )
                hsts.exploitability_rationale = (
                    "Conditionally exploitable. Requires active MITM position, "
                    "but the presence of session tokens or sensitive data on "
                    "this endpoint makes this a meaningful risk."
                )

        return results

    def _apply_exploitability_gates(
            self, results: List[AgentResult]
    ) -> List[AgentResult]:
        """
        Apply exploitability gates to HIGH/CRITICAL findings.

        Args:
            results: List of findings

        Returns:
            Results with gated severities
        """
        for result in results:
            if result.severity not in [Severity.HIGH, Severity.CRITICAL]:
                continue

            gates_failed, gate_details = self._evaluate_exploitability_gates(result)

            if gates_failed >= OrchestratorConfig.GATES_REQUIRED_FOR_DOWNGRADE:
                self._apply_gate_downgrade(result, gates_failed, gate_details)

        return results

    def _evaluate_exploitability_gates(
            self, result: AgentResult
    ) -> tuple[int, List[str]]:
        """
        Evaluate exploitability gates for a result.

        Returns:
            Tuple of (gates_failed_count, gate_details)
        """
        gates_failed = 0
        gate_details = []

        # Bypass gates for pre-verified dependency vulnerabilities
        if result.vulnerability_type == VulnerabilityType.VULNERABLE_DEPENDENCY:
            return 0, []

        # Gate 1: User Interaction Required
        if self._requires_user_interaction(result):
            gates_failed += 1
            gate_details.append("requires user interaction")

        # Gate 2: Authentication Required
        if self._requires_authentication(result):
            gates_failed += 1
            gate_details.append("requires authentication")

        # Gate 3: Sensitive Data Involvement
        if not self._involves_sensitive_data(result):
            gates_failed += 1
            gate_details.append("no sensitive data directly involved")

        # Gate 4: Cross-User Impact
        if not self._has_cross_user_impact(result):
            gates_failed += 1
            gate_details.append("impact limited to single user/session")

        return gates_failed, gate_details

    def _requires_user_interaction(self, result: AgentResult) -> bool:
        """Check if vulnerability requires user interaction."""
        user_interaction_vulns = [
            VulnerabilityType.XSS_REFLECTED,
            VulnerabilityType.XSS_STORED,
            VulnerabilityType.XSS_DOM,
            VulnerabilityType.CSRF
        ]
        return result.vulnerability_type in user_interaction_vulns

    def _requires_authentication(self, result: AgentResult) -> bool:
        """Check if vulnerability requires authentication."""
        auth_keywords = [
            "authenticated", "logged in", "session required", "auth required"
        ]
        return any(
            kw in result.description.lower() or
            kw in result.exploitability_rationale.lower()
            for kw in auth_keywords
        )

    def _involves_sensitive_data(self, result: AgentResult) -> bool:
        """Check if vulnerability involves sensitive data."""
        text_to_check = " ".join([
            result.description.lower(),
            result.evidence.lower(),
            result.title.lower()
        ])
        return any(
            kw in text_to_check
            for kw in SensitiveDataKeywords.KEYWORDS
        )

    def _has_cross_user_impact(self, result: AgentResult) -> bool:
        """Check if vulnerability has cross-user impact."""
        cross_user_vulns = [
            VulnerabilityType.XSS_STORED,
            VulnerabilityType.IDOR
        ]
        return result.vulnerability_type in cross_user_vulns

    def _apply_gate_downgrade(
            self,
            result: AgentResult,
            gates_failed: int,
            gate_details: List[str]
    ) -> None:
        """Apply severity downgrade based on gates."""
        original_severity = result.severity

        if result.severity == Severity.CRITICAL:
            result.severity = Severity.HIGH
        elif result.severity == Severity.HIGH:
            result.severity = Severity.MEDIUM

        result.confidence = max(
            result.confidence - OrchestratorConfig.CONFIDENCE_PENALTY_GATES,
            50
        )
        result.ai_analysis += (
            f"\n\n[Exploitability Gate] Severity adjusted from "
            f"{original_severity.value} to {result.severity.value}. "
            f"Factors: {', '.join(gate_details)}."
        )

        logger.info(
            f"Gated '{result.title}': {original_severity.value} → "
            f"{result.severity.value} ({gates_failed} gates failed)"
        )

    def _calculate_verdicts(
            self, results: List[AgentResult]
    ) -> List[AgentResult]:
        """
        Calculate final verdicts and split confidence metrics.

        Args:
            results: List of findings

        Returns:
            Results with verdicts calculated
        """
        for result in results:
            if result.is_suppressed:
                continue

            # Split confidence metrics (normalize to 0.0-1.0 range for DB constraints)
            result.detection_confidence = result.confidence / 100.0
            result.exploit_confidence = self._calculate_exploit_confidence(result) / 100.0

            # Determine verdict
            result.final_verdict = self._determine_verdict(result)
            result.action_required = self._should_require_action(result)

            # Set exploitability rationale if not already set
            if not result.exploitability_rationale:
                result.exploitability_rationale = self._generate_rationale(result)

        return results

    def _calculate_exploit_confidence(self, result: AgentResult) -> float:
        """Calculate exploit confidence based on severity."""
        confidence_map = {
            Severity.CRITICAL: 90.0,
            Severity.HIGH: 70.0,
            Severity.MEDIUM: 40.0,
            Severity.LOW: 10.0,
            Severity.INFO: 0.0
        }

        base_confidence = confidence_map.get(result.severity, 0.0)

        # Adjust for exploitability gate
        if "[Exploitability Gate]" in result.ai_analysis:
            base_confidence = max(0, base_confidence - 30)

        return base_confidence

    def _determine_verdict(self, result: AgentResult) -> str:
        """Determine final verdict for a result."""
        # Special case: Security headers
        if (result.vulnerability_type == VulnerabilityType.SECURITY_MISCONFIG and
                "header" in result.title.lower()):
            return "DEFENSE_IN_DEPTH"

        # Sensitive data with low confidence
        if (result.vulnerability_type == VulnerabilityType.SENSITIVE_DATA_EXPOSURE and
                result.confidence < 70):
            if result.severity in [Severity.HIGH, Severity.CRITICAL]:
                result.severity = Severity.MEDIUM
            return "ACTION_REQUIRED"

        # High severity = confirmed
        if result.severity in [Severity.HIGH, Severity.CRITICAL]:
            return "CONFIRMED_VULNERABILITY"

        # Medium severity = action required
        if result.severity == Severity.MEDIUM:
            return "ACTION_REQUIRED"

        # Low severity = best practice
        return "BEST_PRACTICE"

    def _should_require_action(self, result: AgentResult) -> bool:
        """Determine if action is required."""
        return result.final_verdict != "FALSE_POSITIVE"

    def _generate_rationale(self, result: AgentResult) -> str:
        """Generate exploitability rationale."""
        if result.final_verdict == "DEFENSE_IN_DEPTH":
            return (
                "This finding represents a defense-in-depth hardening "
                "opportunity. It is not directly exploitable and does not "
                "indicate a security breach."
            )

        if result.final_verdict == "ACTION_REQUIRED":
            return (
                "Pattern-only match for sensitive data. Contextual "
                "confirmation required to ensure this is not a false "
                "positive or placeholder."
            )

        return "Standard exploitability assessment applies."

    def _calculate_scope_impact(
            self, results: List[AgentResult]
    ) -> List[AgentResult]:
        """
        Calculate scope and systemic impact for findings.

        Args:
            results: List of findings

        Returns:
            Results with scope impact calculated
        """
        # Group by type
        by_type = self._categorize_by_type(results)

        for result in results:
            similar = by_type.get(result.vulnerability_type, [])
            unique_endpoints = len(set(s.url for s in similar))
            unique_methods = list(set(s.method for s in similar))

            is_systemic = unique_endpoints > 2

            result.scope_impact = {
                "affected_endpoints": unique_endpoints,
                "affected_methods": unique_methods,
                "is_systemic": is_systemic,
                "summary": (
                    f"Affected Endpoints: {unique_endpoints} | "
                    f"Systemic: {'Yes' if is_systemic else 'No'}"
                )
            }

            if (is_systemic and
                    result.vulnerability_type == VulnerabilityType.SECURITY_MISCONFIG):
                result.scope_impact["description"] = "Global Policy Issue"

        return results

    # ==================== Deduplication ====================

    def _deduplicate_results_similarity(
            self, results: List[AgentResult]
    ) -> List[AgentResult]:
        """
        Remove duplicate vulnerability findings using similarity scoring.

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

            # Find similar results
            similar_indices = self._find_similar_results(
                i, result1, results, processed
            )

            # Merge if multiple similar results found
            if len(similar_indices) > 1:
                similar_results = [results[idx] for idx in similar_indices]
                merged = self._merge_results(similar_results)
                unique_results.append(merged)
            else:
                unique_results.append(result1)

            # Mark all as processed
            processed.update(similar_indices)

        logger.info(
            f"Deduplicated {len(results)} → {len(unique_results)} results"
        )
        return unique_results

    def _find_similar_results(
            self,
            base_index: int,
            base_result: AgentResult,
            all_results: List[AgentResult],
            processed: Set[int]
    ) -> List[int]:
        """Find all results similar to base result."""
        similar = [base_index]

        for j in range(base_index + 1, len(all_results)):
            if j in processed:
                continue

            similarity = self._calculate_similarity(base_result, all_results[j])

            if similarity >= OrchestratorConfig.SIMILARITY_THRESHOLD:
                similar.append(j)

        return similar

    def _calculate_similarity(
            self, result1: AgentResult, result2: AgentResult
    ) -> float:
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

        # Special handling for vulnerable dependencies - must be same package/title
        if result1.vulnerability_type == VulnerabilityType.VULNERABLE_DEPENDENCY:
            # Titles contain package name and summary - must be high similarity
            title_sim = SequenceMatcher(None, result1.title, result2.title).ratio()
            if title_sim < 0.9:
                return 0.0

        # Compare URLs
        url1, url2 = result1.url, result2.url
        url_similarity = SequenceMatcher(None, url1, url2).ratio()

        # Explicit path sensitivity - if repo paths differ, they are not similar
        if "github.com" in url1 and "github.com" in url2:
            try:
                # Extract path after /blob/branch/
                path1 = url1.split('/blob/')[1].split('/', 1)[1].split('#')[0]
                path2 = url2.split('/blob/')[1].split('/', 1)[1].split('#')[0]
                if path1 != path2:
                    return 0.0
            except (IndexError, AttributeError):
                pass

        # Compare parameters
        param_similarity = self._compare_parameters(result1, result2)

        # Compare methods
        method_similarity = 1.0 if result1.method == result2.method else 0.0

        # Weighted average
        similarity = (
                url_similarity * 0.5 +
                param_similarity * 0.3 +
                method_similarity * 0.2
        )

        return similarity

    def _compare_parameters(
            self, result1: AgentResult, result2: AgentResult
    ) -> float:
        """Compare parameter similarity between two results."""
        if result1.parameter and result2.parameter:
            return SequenceMatcher(
                None, result1.parameter, result2.parameter
            ).ratio()
        elif result1.parameter or result2.parameter:
            return 0.5  # One has parameter, one doesn't
        return 1.0  # Both have no parameters

    def _merge_results(self, results: List[AgentResult]) -> AgentResult:
        """
        Merge multiple similar results into one.

        Args:
            results: List of similar results to merge

        Returns:
            Merged result

        Raises:
            ValueError: If results list is empty
        """
        if not results:
            raise ValueError("Cannot merge empty results list")

        # Use result with highest confidence as base
        base = max(results, key=lambda r: r.confidence)

        # Aggregate metrics
        max_confidence = max(r.confidence for r in results)
        max_likelihood = max(r.likelihood for r in results)
        max_impact = max(r.impact for r in results)

        # Combine evidence
        combined_evidence = self._combine_evidence(results, base)

        # Combine AI analysis
        combined_analysis = self._combine_analysis(results, base)

        # Create merged result
        merged = AgentResult(
            agent_name=f"{base.agent_name} (+{len(results) - 1} similar)",
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
            likelihood=max_likelihood,
            impact=max_impact,
            exploitability_rationale=base.exploitability_rationale
        )

        return merged

    def _combine_evidence(
            self, results: List[AgentResult], base: AgentResult
    ) -> str:
        """Combine evidence from multiple results."""
        all_evidence = []
        for r in results:
            if r.evidence and r.evidence not in all_evidence:
                all_evidence.append(r.evidence)

        return " | ".join(all_evidence) if all_evidence else base.evidence

    def _combine_analysis(
            self, results: List[AgentResult], base: AgentResult
    ) -> str:
        """Combine AI analysis from multiple results."""
        all_analysis = [r.ai_analysis for r in results if r.ai_analysis]
        unique_analysis = set(all_analysis)
        return " / ".join(unique_analysis) if unique_analysis else base.ai_analysis

    def _sort_results(self, results: List[AgentResult]) -> List[AgentResult]:
        """Sort results by severity and confidence."""
        def safe_sort_key(res):
            try:
                # Severity index (handle invalid severity)
                if isinstance(res.severity, Severity):
                    severity_idx = list(Severity).index(res.severity)
                else:
                    severity_idx = list(Severity).index(Severity.LOW)
            except (ValueError, AttributeError):
                severity_idx = list(Severity).index(Severity.LOW)
            
            try:
                # Confidence (handle strings/None)
                if isinstance(res.confidence, (int, float)):
                    conf = res.confidence
                elif isinstance(res.confidence, str) and res.confidence.isdigit():
                    conf = int(res.confidence)
                else:
                    conf = 0.0
            except (ValueError, TypeError):
                conf = 0.0
                
            return (severity_idx, -conf)

        return sorted(results, key=safe_sort_key)

    # ==================== Metrics ====================

    def _calculate_scan_metrics(self) -> None:
        """Calculate scan quality metrics for internal tracking."""
        if not self.results:
            self.scan_metrics = ScanMetrics()
            return

        findings_count = len(self.results)

        # Severity distribution
        severity_dist = self._calculate_severity_distribution()

        # Evidence completeness
        evidence_completeness = self._calculate_evidence_completeness()

        # Chained findings ratio
        chained_ratio = self._calculate_chained_ratio()

        # Average confidence
        avg_confidence = sum(r.confidence for r in self.results) / findings_count

        # Unique endpoints
        unique_endpoints = len(set(r.url for r in self.results))

        # Findings per endpoint
        findings_per_endpoint = (
            findings_count / unique_endpoints if unique_endpoints > 0 else 0
        )

        # Gated and downgraded counts
        gated_count = sum(
            1 for r in self.results
            if "[Exploitability Gate]" in r.ai_analysis
        )
        evidence_downgraded = sum(
            1 for r in self.results
            if "[Evidence Gate]" in r.ai_analysis
        )

        # Calculate signal quality score
        signal_quality = self._calculate_signal_quality_score(
            evidence_completeness,
            chained_ratio,
            findings_per_endpoint,
            avg_confidence
        )

        self.scan_metrics = ScanMetrics(
            findings_count=findings_count,
            severity_distribution=severity_dist,
            evidence_completeness_pct=evidence_completeness,
            chained_findings_ratio_pct=chained_ratio,
            average_confidence=avg_confidence,
            unique_endpoints_tested=unique_endpoints,
            findings_per_endpoint=findings_per_endpoint,
            exploitability_gated_count=gated_count,
            evidence_downgraded_count=evidence_downgraded,
            signal_quality_score=signal_quality
        )

        logger.info(f"Scan Metrics: {self.scan_metrics.to_dict()}")

    def _calculate_severity_distribution(self) -> Dict[str, int]:
        """Calculate distribution of findings by severity."""
        dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in self.results:
            dist[r.severity.value] = dist.get(r.severity.value, 0) + 1
        return dist

    def _calculate_evidence_completeness(self) -> float:
        """Calculate percentage of findings with evidence."""
        if not self.results:
            return 0.0

        with_evidence = sum(
            1 for r in self.results
            if r.evidence and len(r.evidence.strip()) > OrchestratorConfig.MIN_EVIDENCE_LENGTH
        )
        return (with_evidence / len(self.results)) * 100

    def _calculate_chained_ratio(self) -> float:
        """Calculate percentage of correlated findings."""
        if not self.results:
            return 0.0

        chained_count = sum(
            1 for r in self.results
            if "[Correlation]" in r.ai_analysis
        )
        return (chained_count / len(self.results)) * 100

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
        """
        # Evidence score (0-30)
        evidence_score = (evidence_pct / 100) * 30

        # Chained score (0-25)
        chained_score = min(
            (chained_pct / OrchestratorConfig.MAX_CHAINED_RATIO_FOR_SCORE) * 25,
            25
        )

        # Noise score (0-25) - penalize too many findings per endpoint
        if findings_per_ep <= 1:
            noise_score = 25
        elif findings_per_ep >= OrchestratorConfig.MAX_FINDINGS_PER_ENDPOINT:
            noise_score = 0
        else:
            ratio = (findings_per_ep - 1) / (OrchestratorConfig.MAX_FINDINGS_PER_ENDPOINT - 1)
            noise_score = 25 - (ratio * 25)

        # Confidence score (0-20)
        confidence_score = (avg_confidence / 100) * 20

        return evidence_score + chained_score + noise_score + confidence_score

    # ==================== Progress and State ====================

    async def _update_progress(self, progress: int, status: str) -> None:
        """
        Update scan progress.

        Args:
            progress: Progress percentage (0-100)
            status: Status message
        """
        self.progress = progress
        logger.info(f"Progress: {progress}% - {status}")

        if self.on_progress:
            await self.on_progress(progress, status)

    def cancel_scan(self) -> None:
        """Request cancellation of the current scan."""
        self.should_cancel = True
        logger.info("Scan cancellation requested")

    async def cleanup(self) -> None:
        """Clean up resources by closing all registered agents."""
        self.is_running = False
        logger.info(f"Cleaning up orchestrator and {len(self.agents)} agents...")
        
        # Close all agents concurrently
        tasks = [agent.close() for agent in self.agents.values()]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            
        logger.info("Cleanup complete (all agent clients closed)")

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of scan results including failures.

        Returns:
            Summary dictionary with detailed metrics
        """
        summary = {
            "total": len(self.results),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed_count": 0,
            "by_type": {},
            "by_agent": {},
            "by_verdict": {},
            "failed_agents": self.failed_agents,
            "scan_context_summary": {},
            "metrics": None
        }

        # Count by severity and verdict
        for result in self.results:
            severity_key = result.severity.value
            summary[severity_key] = summary.get(severity_key, 0) + 1

            if result.is_suppressed:
                summary["suppressed_count"] += 1

            if result.final_verdict:
                verdict_count = summary["by_verdict"].get(result.final_verdict, 0)
                summary["by_verdict"][result.final_verdict] = verdict_count + 1

            # Count by type
            type_key = result.vulnerability_type.value
            type_count = summary["by_type"].get(type_key, 0)
            summary["by_type"][type_key] = type_count + 1

            # Count by agent
            agent_count = summary["by_agent"].get(result.agent_name, 0)
            summary["by_agent"][result.agent_name] = agent_count + 1

        # Add scan context summary
        if self.scan_context:
            summary["scan_context_summary"] = {
                "discovered_credentials": len(
                    self.scan_context.discovered_credentials
                ),
                "has_database_info": self.scan_context.has_database_info(),
                "session_tokens": len(self.scan_context.session_tokens),
                "authenticated": self.scan_context.authenticated
            }

        # Add metrics
        if self.scan_metrics:
            summary["metrics"] = self.scan_metrics.to_dict()

        return summary


# ==================== Singleton Instance ====================

# Singleton orchestrator instance for global use
orchestrator = AgentOrchestrator()