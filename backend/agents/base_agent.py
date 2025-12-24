"""
Base Security Agent - Abstract base class for all security testing agents.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, TYPE_CHECKING
from enum import Enum
import httpx
import asyncio
import time
from datetime import datetime

from core.groq_client import gemini_client
from core.rate_limiter import get_rate_limiter, AdaptiveRateLimiter
from core.request_cache import get_request_cache, RequestCache
from core.evidence_tracker import get_evidence_tracker, EvidenceChain, DetectionMethod
from core.diff_detector import DiffDetector, ResponseDiff
from models.vulnerability import Severity, VulnerabilityType

if TYPE_CHECKING:
    from core.scan_context import ScanContext


class _CachedResponse:
    """Mock response object for cached responses."""
    
    def __init__(self, text: str, status_code: int, headers: Dict[str, str]):
        self.text = text
        self.status_code = status_code
        self.headers = headers
        self.content = text.encode('utf-8')
    
    def json(self):
        import json
        return json.loads(self.text)


@dataclass
class AgentResult:
    """Result from a security agent scan."""
    agent_name: str
    vulnerability_type: VulnerabilityType
    is_vulnerable: bool
    severity: Severity
    confidence: float  # 0-100
    
    # Location
    url: str
    parameter: Optional[str] = None
    method: str = "GET"
    
    # Details
    title: str = ""
    description: str = ""
    evidence: str = ""
    
    # Request/Response
    request_data: Dict[str, Any] = field(default_factory=dict)
    response_snippet: str = ""
    
    # AI Analysis
    ai_analysis: str = ""
    
    # Remediation
    remediation: str = ""
    remediation_code: str = ""
    reference_links: List[str] = field(default_factory=list)
    
    # OWASP Mapping
    owasp_category: str = ""
    cwe_id: str = ""
    
    # Metadata
    detected_at: datetime = field(default_factory=datetime.utcnow)
    cvss_score: Optional[float] = None
    
    # Risk Assessment
    likelihood: float = 0.0
    impact: float = 0.0
    exploitability_rationale: str = ""
    
    # Evidence Chain (optional)
    evidence_chain_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_name": self.agent_name,
            "vulnerability_type": self.vulnerability_type.value,
            "is_vulnerable": self.is_vulnerable,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "ai_analysis": self.ai_analysis,
            "remediation": self.remediation,
            "owasp_category": self.owasp_category,
            "cwe_id": self.cwe_id,
            "detected_at": self.detected_at.isoformat(),
            "cvss_score": self.cvss_score,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "exploitability_rationale": self.exploitability_rationale,
        }


class BaseSecurityAgent(ABC):
    """
    Abstract base class for security testing agents.
    
    Each specialized agent (SQLi, XSS, etc.) inherits from this class
    and implements the specific testing logic.
    """
    
    # Agent metadata - override in subclasses
    agent_name: str = "base_agent"
    agent_description: str = "Base security agent"
    vulnerability_types: List[VulnerabilityType] = []
    
    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 3,
        use_rate_limiting: bool = True,
        use_caching: bool = True
    ):
        """
        Initialize the security agent.
        
        Args:
            timeout: HTTP request timeout in seconds
            max_retries: Maximum number of retry attempts
            use_rate_limiting: Whether to use adaptive rate limiting
            use_caching: Whether to cache responses
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.use_rate_limiting = use_rate_limiting
        self.use_caching = use_caching
        self.results: List[AgentResult] = []
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,  # Allow self-signed certs for testing
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Matrix/1.0"}
        )
        self.evidence_tracker = get_evidence_tracker()
        self.diff_detector = DiffDetector()
        self.gemini = gemini_client
        self.rate_limiter: AdaptiveRateLimiter = get_rate_limiter()
        self.cache: RequestCache = get_request_cache()
        
        # Request statistics
        self.request_stats = {
            "total_requests": 0,
            "cached_responses": 0,
            "rate_limit_waits": 0,
            "total_wait_time": 0.0,
            "errors": 0
        }
    
    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()
    
    @abstractmethod
    async def scan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str] = None,
        scan_context: Optional["ScanContext"] = None
    ) -> List[AgentResult]:
        """
        Perform security scan on target.
        
        Args:
            target_url: Base URL of the target application
            endpoints: List of discovered endpoints to test
            technology_stack: Detected technology stack
            scan_context: Shared context for inter-agent communication
            
        Returns:
            List of AgentResult objects for any vulnerabilities found
        """
        pass
    
    def _read_context(self, scan_context: Optional["ScanContext"], key: str) -> Any:
        """
        Helper to read from scan context safely.
        
        Args:
            scan_context: Scan context object
            key: Attribute to read
            
        Returns:
            Value from context or None
        """
        if scan_context is None:
            return None
        return getattr(scan_context, key, None)
    
    def _write_context(self, scan_context: Optional["ScanContext"], **kwargs):
        """
        Helper to write to scan context safely.
        
        Args:
            scan_context: Scan context object
            **kwargs: Attributes to set
        """
        if scan_context is None:
            return
        
        for key, value in kwargs.items():
            if hasattr(scan_context, key):
                setattr(scan_context, key, value)
    
    async def make_request(
        self,
        url: str,
        method: str = "GET",
        data: Dict = None,
        headers: Dict = None,
        params: Dict = None,
        use_cache: bool = True,
        skip_rate_limit: bool = False
    ) -> Optional[httpx.Response]:
        """
        Make an HTTP request with rate limiting, caching, and retry logic.
        
        Args:
            url: Target URL
            method: HTTP method
            data: POST/PUT body data
            headers: Request headers
            params: Query parameters
            use_cache: Whether to use caching for this request
            skip_rate_limit: Whether to skip rate limiting
            
        Returns:
            Response object or None if all retries failed
        """
        # Ensure URL has a scheme
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        
        self.request_stats["total_requests"] += 1
        
        # Check cache first (for GET requests by default)
        if self.use_caching and use_cache:
            cached = await self.cache.get(url, method, params, data, headers)
            if cached:
                self.request_stats["cached_responses"] += 1
                # Create a mock response-like object
                return _CachedResponse(
                    text=cached.response_text,
                    status_code=cached.status_code,
                    headers=cached.headers
                )
        
        # Apply rate limiting
        if self.use_rate_limiting and not skip_rate_limit:
            wait_time = await self.rate_limiter.acquire(url)
            if wait_time > 0:
                self.request_stats["rate_limit_waits"] += 1
                self.request_stats["total_wait_time"] += wait_time
        
        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                response = await self.http_client.request(
                    method=method,
                    url=url,
                    data=data,
                    headers=headers,
                    params=params
                )
                response_time = time.time() - start_time
                
                # Report to rate limiter
                if self.use_rate_limiting:
                    retry_after = None
                    if 'Retry-After' in response.headers:
                        try:
                            retry_after = int(response.headers['Retry-After'])
                        except ValueError:
                            pass
                    await self.rate_limiter.report_response(
                        url, response.status_code, response_time, retry_after
                    )
                
                # Cache successful responses
                if self.use_caching and use_cache and response.status_code < 500:
                    await self.cache.set(
                        url=url,
                        method=method,
                        response_text=response.text,
                        status_code=response.status_code,
                        response_headers=dict(response.headers),
                        params=params,
                        data=data,
                        request_headers=headers
                    )
                
                return response
                
            except Exception as e:
                self.request_stats["errors"] += 1
                if attempt == self.max_retries - 1:
                    print(f"[{self.agent_name}] Request failed after {self.max_retries} attempts: {e}")
                    return None
                await asyncio.sleep(1)  # Wait before retry
        
        return None
    
    def get_request_stats(self) -> Dict[str, Any]:
        """Get request statistics for this agent."""
        stats = self.request_stats.copy()
        if stats["total_requests"] > 0:
            stats["cache_hit_rate"] = (stats["cached_responses"] / stats["total_requests"]) * 100
        else:
            stats["cache_hit_rate"] = 0.0
        return stats
    
    def calculate_cvss_score(self, severity: Severity) -> float:
        """
        Calculate approximate CVSS score based on severity.
        
        Args:
            severity: Vulnerability severity
            
        Returns:
            CVSS score (0.0 - 10.0)
        """
        cvss_map = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 3.0,
            Severity.INFO: 0.0
        }
        return cvss_map.get(severity, 0.0)
    
    async def analyze_with_ai(
        self,
        vulnerability_type: str,
        context: str,
        response_data: str
    ) -> Dict[str, Any]:
        """
        Use Gemini AI to analyze potential vulnerability.
        
        Args:
            vulnerability_type: Type of vulnerability being tested
            context: Context about the test
            response_data: Response data to analyze
            
        Returns:
            AI analysis results
        """
        return await self.gemini.analyze_vulnerability(
            vulnerability_type=vulnerability_type,
            context=context,
            response_data=response_data
        )
    
    async def generate_remediation(
        self,
        vulnerability_type: str,
        code_context: str,
        technology_stack: List[str]
    ) -> Dict[str, Any]:
        """
        Generate remediation recommendations using AI.
        
        Args:
            vulnerability_type: Type of vulnerability
            code_context: Code or context where vulnerability exists
            technology_stack: Technologies used
            
        Returns:
            Remediation recommendations
        """
        return await self.gemini.generate_fix_recommendation(
            vulnerability_type=vulnerability_type,
            code_context=code_context,
            technology_stack=technology_stack
        )
    
    def create_result(
        self,
        vulnerability_type: VulnerabilityType,
        is_vulnerable: bool,
        severity: Severity,
        confidence: float,
        url: str,
        title: str,
        description: str,
        likelihood: float = 0.0,
        impact: float = 0.0,
        exploitability_rationale: str = "",
        **kwargs
    ) -> AgentResult:
        """
        Create a standardized AgentResult.
        
        Args:
            vulnerability_type: Type of vulnerability
            is_vulnerable: Whether vulnerability was confirmed
            severity: Severity level
            confidence: Confidence score (0-100)
            url: Affected URL
            title: Vulnerability title
            description: Detailed description
            likelihood: Likelihood score (0-10)
            impact: Impact score (0-10)
            exploitability_rationale: Explanation of exploitability
            **kwargs: Additional fields
            
        Returns:
            AgentResult object
        """
        return AgentResult(
            agent_name=self.agent_name,
            vulnerability_type=vulnerability_type,
            is_vulnerable=is_vulnerable,
            severity=severity,
            confidence=confidence,
            url=url,
            title=title,
            description=description,
            cvss_score=self.calculate_cvss_score(severity),
            likelihood=likelihood,
            impact=impact,
            exploitability_rationale=exploitability_rationale,
            **kwargs
        )

    def create_result_from_ai(
        self,
        ai_analysis: Dict[str, Any],
        vulnerability_type: VulnerabilityType,
        url: str,
        title: str,
        description: str,
        severity: Severity,
        **kwargs
    ) -> AgentResult:
        """Helper to create result from AI analysis dict."""
        # Extract likelihood - AI returns as "likelihood" (float 0-10)
        likelihood_raw = ai_analysis.get("likelihood", 0.0)
        try:
            likelihood = float(likelihood_raw) if likelihood_raw is not None else 0.0
        except (ValueError, TypeError):
            likelihood = 0.0
        
        # Extract impact - AI returns as "impact_score" (float 0-10)
        # Fall back to "impact" but ensure it's a number, not a description string
        impact_raw = ai_analysis.get("impact_score", ai_analysis.get("impact", 0.0))
        try:
            impact = float(impact_raw) if impact_raw is not None else 0.0
        except (ValueError, TypeError):
            # If it's a string description, use severity-based default
            severity_impact_map = {
                Severity.CRITICAL: 9.0,
                Severity.HIGH: 7.0,
                Severity.MEDIUM: 5.0,
                Severity.LOW: 3.0,
                Severity.INFO: 1.0
            }
            impact = severity_impact_map.get(severity, 5.0)
        
        # Extract exploitability rationale - could be in multiple fields
        exploitability = ai_analysis.get("exploitability_rationale", "")
        if not exploitability:
            exploitability = ai_analysis.get("exploitability_conditions", "")
        
        return self.create_result(
            vulnerability_type=vulnerability_type,
            is_vulnerable=ai_analysis.get("is_vulnerable", True),
            severity=severity,
            confidence=ai_analysis.get("confidence", 85),
            url=url,
            title=title,
            description=description,
            ai_analysis=ai_analysis.get("reason", ""),
            likelihood=likelihood,
            impact=impact,
            exploitability_rationale=exploitability,
            **kwargs
        )    
    def create_evidence_chain(
        self,
        url: str,
        parameter: str,
        vuln_type: VulnerabilityType,
        detection_method: DetectionMethod
    ) -> EvidenceChain:
        """
        Create a new evidence chain for tracking vulnerability detection.
        
        Args:
            url: Target URL
            parameter: Vulnerable parameter
            vuln_type: Vulnerability type
            detection_method: Detection method used
            
        Returns:
            New evidence chain
        """
        chain_id = self.evidence_tracker.generate_chain_id(url, parameter or "", vuln_type.value)
        chain = self.evidence_tracker.create_chain(chain_id, detection_method)
        return chain
    
    def add_evidence(
        self,
        chain: EvidenceChain,
        request: Dict[str, Any],
        response_text: str,
        response_time_ms: float,
        status_code: int,
        note: Optional[str] = None
    ) -> None:
        """
        Add request/response interaction to evidence chain.
        
        Args:
            chain: Evidence chain
            request: Request data
            response_text: Response content
            response_time_ms: Response time in milliseconds
            status_code: HTTP status code
            note: Optional note about this interaction
        """
        chain.add_interaction(
            request=request,
            response={"text": response_text[:1000]},  # Truncate large responses
            response_time_ms=response_time_ms,
            status_code=status_code,
            note=note
        )
    
    def set_baseline(
        self,
        chain: EvidenceChain,
        request: Dict[str, Any],
        response_text: str,
        response_time_ms: float,
        status_code: int
    ) -> None:
        """
        Set baseline response for comparison.
        
        Args:
            chain: Evidence chain
            request: Request data
            response_text: Response content
            response_time_ms: Response time
            status_code: HTTP status code
        """
        chain.set_baseline(
            request=request,
            response={"text": response_text[:1000]},
            response_time_ms=response_time_ms,
            status_code=status_code
        )
    
    def compare_responses(
        self,
        baseline_response: str,
        test_response: str,
        normalize: bool = True
    ) -> ResponseDiff:
        """
        Compare two responses to detect significant changes.
        
        Useful for blind vulnerability detection where responses
        have subtle differences.
        
        Args:
            baseline_response: Original/normal response
            test_response: Response after exploitation attempt
            normalize: Whether to normalize responses
            
        Returns:
            ResponseDiff with detailed comparison
        """
        return self.diff_detector.compare_responses(
            baseline_response,
            test_response,
            normalize=normalize
        )
    
    def detect_boolean_based(
        self,
        baseline: str,
        true_response: str,
        false_response: str
    ) -> Dict[str, Any]:
        """
        Detect boolean-based blind vulnerabilities.
        
        Args:
            baseline: Normal response
            true_response: Response when condition is TRUE
            false_response: Response when condition is FALSE
            
        Returns:
            Analysis of boolean behavior
        """
        return self.diff_detector.detect_boolean_based(
            baseline, true_response, false_response
        )