"""
Base Security Agent - Abstract base class for all security testing agents.

This module provides the foundational infrastructure for all specialized security
testing agents (SQLi, XSS, CSRF, etc.). It handles:
- HTTP request/response lifecycle with caching and rate limiting
- AI-powered vulnerability analysis via Gemini
- Evidence tracking and response comparison
- CVSS scoring and remediation generation
- Inter-agent communication via ScanContext

Example:
    class CustomAgent(BaseSecurityAgent):
        agent_name = "custom_security"
        agent_description = "Custom vulnerability scanner"
        vulnerability_types = [VulnerabilityType.CUSTOM]

        async def scan(self, target_url, endpoints, technology_stack=None, scan_context=None):
            results = []
            for endpoint in endpoints:
                response = await self.make_request(endpoint['url'])
                if self._detect_vulnerability(response):
                    result = self.create_result(...)
                    results.append(result)
            return results
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, TYPE_CHECKING, Protocol
from enum import Enum
import httpx
import asyncio
import time
import logging
import json
import re
from datetime import datetime
from urllib.parse import urlparse

# from core import hf_client
from core.groq_client import scanner_generate
from core.rate_limiter import get_rate_limiter, AdaptiveRateLimiter
from core.request_cache import get_request_cache, RequestCache
from core.evidence_tracker import get_evidence_tracker, EvidenceChain, DetectionMethod
from core.diff_detector import DiffDetector, ResponseDiff
from models.vulnerability import Severity, VulnerabilityType

if TYPE_CHECKING:
    from core.scan_context import ScanContext

# Configure logging
logger = logging.getLogger(__name__)


# ============================================================================
# CONFIGURATION CLASSES
# ============================================================================

class AgentConfig:
    """Configuration constants for security agents."""

    # HTTP Request Settings
    DEFAULT_TIMEOUT = 30.0
    DEFAULT_MAX_RETRIES = 3
    RETRY_BACKOFF_BASE = 1.0  # Base wait time for exponential backoff
    MAX_RETRY_BACKOFF = 10.0  # Maximum backoff time

    # Response Handling
    MAX_CACHED_RESPONSE_SIZE = 1000  # Characters to store in evidence
    RESPONSE_SNIPPET_SIZE = 500  # Default snippet size

    # CVSS Scoring
    CVSS_CRITICAL = 9.5
    CVSS_HIGH = 7.5
    CVSS_MEDIUM = 5.5
    CVSS_LOW = 3.0
    CVSS_INFO = 0.0

    # Severity to Impact Mapping (0-10 scale)
    SEVERITY_IMPACT_MAP = {
        Severity.CRITICAL: 9.0,
        Severity.HIGH: 7.0,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 3.0,
        Severity.INFO: 1.0
    }

    # User Agent
    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36 Matrix/1.0"
    )


class HTTPMethods:
    """Standard HTTP methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


# ============================================================================
# CUSTOM EXCEPTIONS
# ============================================================================

class AgentException(Exception):
    """Base exception for agent-related errors."""
    pass


class RequestException(AgentException):
    """Exception raised when HTTP requests fail."""

    def __init__(self, message: str, url: str, method: str, attempt: int):
        self.url = url
        self.method = method
        self.attempt = attempt
        super().__init__(f"{message} (url={url}, method={method}, attempt={attempt})")


class ValidationException(AgentException):
    """Exception raised when input validation fails."""
    pass


class AIAnalysisException(AgentException):
    """Exception raised when AI analysis fails."""
    pass


# ============================================================================
# TYPE DEFINITIONS
# ============================================================================

class ResponseLike(Protocol):
    """Protocol for HTTP response objects."""
    text: str
    status_code: int
    headers: Dict[str, str]
    content: bytes

    def json(self) -> Any: ...


@dataclass
class RequestStats:
    """Statistics for agent HTTP requests."""
    total_requests: int = 0
    cached_responses: int = 0
    rate_limit_waits: int = 0
    total_wait_time: float = 0.0
    errors: int = 0

    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate as percentage."""
        if self.total_requests == 0:
            return 0.0
        return (self.cached_responses / self.total_requests) * 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "total_requests": self.total_requests,
            "cached_responses": self.cached_responses,
            "rate_limit_waits": self.rate_limit_waits,
            "total_wait_time": round(self.total_wait_time, 2),
            "errors": self.errors,
            "cache_hit_rate": round(self.cache_hit_rate, 2)
        }


# ============================================================================
# MOCK RESPONSE FOR CACHED DATA
# ============================================================================

class CachedResponse:
    """
    Mock response object for cached HTTP responses.

    Provides the same interface as httpx.Response for cached data.
    This allows cached responses to be used transparently with the same
    code that handles live responses.
    """

    def __init__(
            self,
            text: str,
            status_code: int,
            headers: Dict[str, str],
            is_cached: bool = True
    ):
        self.text = text
        self.status_code = status_code
        self.headers = headers
        self.content = text.encode('utf-8')
        self.is_cached = is_cached

    def json(self) -> Any:
        """Parse response text as JSON."""
        import json
        try:
            return json.loads(self.text)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse cached response as JSON: {e}")
            raise


# ============================================================================
# AGENT RESULT DATA CLASS
# ============================================================================

@dataclass
class AgentResult:
    """
    Result from a security agent scan.

    This class encapsulates all information about a detected vulnerability,
    including location, severity, evidence, AI analysis, and remediation.

    Attributes:
        agent_name: Name of the agent that detected the vulnerability
        vulnerability_type: Type of vulnerability (SQL injection, XSS, etc.)
        is_vulnerable: Whether the vulnerability was confirmed
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        confidence: Confidence score 0-100
        url: Affected URL
        parameter: Vulnerable parameter (if applicable)
        method: HTTP method (GET, POST, etc.)
        title: Short vulnerability title
        description: Detailed description
        evidence: Technical evidence (request/response data)
        ai_analysis: AI-generated analysis
        remediation: Remediation recommendations

    Example:
        result = AgentResult(
            agent_name="sql_injection",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            is_vulnerable=True,
            severity=Severity.CRITICAL,
            confidence=95.0,
            url="https://example.com/login",
            parameter="username",
            title="SQL Injection in Login Form",
            description="Time-based blind SQL injection detected..."
        )
    """

    # Core Fields
    agent_name: str
    vulnerability_type: VulnerabilityType
    is_vulnerable: bool
    severity: Severity
    confidence: float  # 0-100

    # Location
    url: str
    parameter: Optional[str] = None
    method: str = HTTPMethods.GET

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

    # Evidence Chain
    evidence_chain_id: Optional[str] = None

    # Final Verdict Layer (from orchestrator intelligence)
    final_verdict: Optional[str] = None
    action_required: bool = True
    detection_confidence: float = 0.0
    exploit_confidence: float = 0.0

    # Status
    is_suppressed: bool = False
    is_false_positive: bool = False
    suppression_reason: Optional[str] = None

    # Scope & Impact
    scope_impact: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format for serialization."""
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
            "remediation_code": self.remediation_code,
            "reference_links": self.reference_links,
            "owasp_category": self.owasp_category,
            "cwe_id": self.cwe_id,
            "detected_at": self.detected_at.isoformat(),
            "cvss_score": self.cvss_score,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "exploitability_rationale": self.exploitability_rationale,
            "final_verdict": self.final_verdict,
            "action_required": self.action_required,
            "detection_confidence": self.detection_confidence,
            "exploit_confidence": self.exploit_confidence,
            "is_suppressed": self.is_suppressed,
            "is_false_positive": self.is_false_positive,
            "suppression_reason": self.suppression_reason,
            "scope_impact": self.scope_impact,
        }


# ============================================================================
# BASE SECURITY AGENT
# ============================================================================

class BaseSecurityAgent(ABC):
    """
    Abstract base class for security testing agents.

    Each specialized agent (SQLi, XSS, etc.) inherits from this class
    and implements the specific testing logic in the scan() method.

    Features:
        - Automatic HTTP request handling with retries and backoff
        - Response caching for efficiency
        - Adaptive rate limiting to avoid overwhelming targets
        - Evidence tracking for vulnerability chains
        - AI-powered vulnerability analysis
        - CVSS scoring and remediation generation

    Attributes:
        agent_name: Unique identifier for this agent
        agent_description: Human-readable description
        vulnerability_types: List of vulnerabilities this agent detects

    Example:
        class SQLInjectionAgent(BaseSecurityAgent):
            agent_name = "sql_injection"
            agent_description = "SQL Injection vulnerability scanner"
            vulnerability_types = [VulnerabilityType.SQL_INJECTION]

            async def scan(self, target_url, endpoints, technology_stack=None, scan_context=None):
                results = []
                for endpoint in endpoints:
                    # Test for SQL injection
                    result = await self._test_sql_injection(endpoint)
                    if result:
                        results.append(result)
                return results
    """

    # Agent metadata - override in subclasses
    agent_name: str = "base_agent"
    agent_description: str = "Base security agent"
    vulnerability_types: List[VulnerabilityType] = []

    def __init__(
            self,
            timeout: float = AgentConfig.DEFAULT_TIMEOUT,
            max_retries: int = AgentConfig.DEFAULT_MAX_RETRIES,
            use_rate_limiting: bool = True,
            use_caching: bool = True
    ):
        """
        Initialize the security agent.

        Args:
            timeout: HTTP request timeout in seconds
            max_retries: Maximum number of retry attempts for failed requests
            use_rate_limiting: Whether to use adaptive rate limiting
            use_caching: Whether to cache successful responses
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.use_rate_limiting = use_rate_limiting
        self.use_caching = use_caching
        self.results: List[AgentResult] = []

        # Initialize HTTP client
        self.http_client = self._create_http_client()

        # self.evidence_tracker = get_evidence_tracker()
        self.diff_detector = DiffDetector()
        self.rate_limiter: AdaptiveRateLimiter = get_rate_limiter()
        self.cache: RequestCache = get_request_cache()

        # Statistics
        self.request_stats = RequestStats()

        logger.info(
            f"Initialized {self.agent_name} agent "
            f"(timeout={timeout}s, retries={max_retries}, "
            f"rate_limiting={use_rate_limiting}, caching={use_caching})"
        )

    def _create_http_client(self) -> httpx.AsyncClient:
        """
        Create configured HTTP client.

        Returns:
            Configured AsyncClient instance
        """
        return httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,  # Allow self-signed certs for testing
            headers={"User-Agent": AgentConfig.DEFAULT_USER_AGENT}
        )

    async def close(self) -> None:
        """
        Clean up resources.

        Should be called when agent is no longer needed to close HTTP connections.
        """
        await self.http_client.aclose()
        logger.debug(f"Closed HTTP client for {self.agent_name}")

    @abstractmethod
    async def scan(
            self,
            target_url: str,
            endpoints: List[Dict[str, Any]],
            technology_stack: Optional[List[str]] = None,
            scan_context: Optional["ScanContext"] = None
    ) -> List[AgentResult]:
        """
        Perform security scan on target.

        This is the main entry point that must be implemented by each agent.

        Args:
            target_url: Base URL of the target application
            endpoints: List of discovered endpoints to test
            technology_stack: Detected technologies (e.g., ["PHP", "MySQL"])
            scan_context: Shared context for inter-agent communication

        Returns:
            List of AgentResult objects for detected vulnerabilities

        Example:
            async def scan(self, target_url, endpoints, technology_stack=None, scan_context=None):
                results = []

                for endpoint in endpoints:
                    url = endpoint['url']

                    # Test for vulnerability
                    response = await self.make_request(url, method="GET")
                    if response and self._is_vulnerable(response):
                        result = self.create_result(
                            vulnerability_type=VulnerabilityType.XSS_REFLECTED,
                            is_vulnerable=True,
                            severity=Severity.HIGH,
                            confidence=90.0,
                            url=url,
                            title="Reflected XSS Detected",
                            description="The application reflects user input without sanitization"
                        )
                        results.append(result)

                return results
        """
        pass

    # ========================================================================
    # CONTEXT MANAGEMENT
    # ========================================================================

    def _read_context(
            self,
            scan_context: Optional["ScanContext"],
            key: str,
            default: Any = None
    ) -> Any:
        """
        Safely read from scan context.

        Args:
            scan_context: Scan context object
            key: Attribute name to read
            default: Default value if key doesn't exist

        Returns:
            Value from context or default

        Example:
            auth_results = self._read_context(scan_context, "auth_results", [])
        """
        if scan_context is None:
            return default
        return getattr(scan_context, key, default)

    def _write_context(
            self,
            scan_context: Optional["ScanContext"],
            **kwargs: Any
    ) -> None:
        """
        Safely write to scan context.

        Args:
            scan_context: Scan context object
            **kwargs: Key-value pairs to set

        Example:
            self._write_context(
                scan_context,
                csrf_tokens=["token1", "token2"],
                session_cookies=cookies
            )
        """
        if scan_context is None:
            return

        for key, value in kwargs.items():
            if hasattr(scan_context, key):
                setattr(scan_context, key, value)
                logger.debug(f"{self.agent_name} updated context: {key}")

    # ========================================================================
    # HTTP REQUEST HANDLING
    # ========================================================================

    def _validate_url(self, url: str) -> str:
        """
        Validate and normalize URL.

        Args:
            url: URL to validate

        Returns:
            Normalized URL with scheme

        Raises:
            ValidationException: If URL is invalid
        """
        if not url:
            raise ValidationException("URL cannot be empty")

        # Add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        # Validate URL structure
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                raise ValidationException(f"Invalid URL: {url}")
        except Exception as e:
            raise ValidationException(f"Invalid URL: {url} - {e}")

        return url

    def _calculate_backoff(self, attempt: int) -> float:
        """
        Calculate exponential backoff time.

        Args:
            attempt: Current attempt number (0-indexed)

        Returns:
            Wait time in seconds
        """
        wait_time = AgentConfig.RETRY_BACKOFF_BASE * (2 ** attempt)
        return min(wait_time, AgentConfig.MAX_RETRY_BACKOFF)

    async def make_request(
            self,
            url: str,
            method: str = HTTPMethods.GET,
            data: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None,
            params: Optional[Dict[str, Any]] = None,
            use_cache: bool = True,
            skip_rate_limit: bool = False
    ) -> Optional[ResponseLike]:
        """
        Make HTTP request with caching, rate limiting, and retry logic.

        This is the primary method for making HTTP requests from agents.
        It handles:
        - URL validation
        - Response caching (for GET requests by default)
        - Adaptive rate limiting
        - Automatic retries with exponential backoff
        - Request statistics tracking

        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            data: Request body data (for POST/PUT)
            headers: Custom request headers
            params: Query parameters
            use_cache: Whether to check cache and cache this request
            skip_rate_limit: Whether to bypass rate limiting

        Returns:
            Response object or None if all retries failed

        Example:
            # Simple GET request
            response = await self.make_request("https://example.com/api/users")

            # POST request with data
            response = await self.make_request(
                url="https://example.com/login",
                method="POST",
                data={"username": "test", "password": "test123"},
                use_cache=False  # Don't cache POST requests
            )
        """
        # Validate URL
        try:
            url = self._validate_url(url)
        except ValidationException as e:
            logger.error(f"[{self.agent_name}] {e}")
            return None

        self.request_stats.total_requests += 1

        # Check cache first
        if self.use_caching and use_cache:
            cached = await self._get_cached_response(url, method, params, data, headers)
            if cached:
                return cached

        # Apply rate limiting
        if self.use_rate_limiting and not skip_rate_limit:
            wait_time = await self.rate_limiter.acquire(url)
            if wait_time > 0:
                self.request_stats.rate_limit_waits += 1
                self.request_stats.total_wait_time += wait_time
                logger.debug(f"[{self.agent_name}] Rate limit wait: {wait_time:.2f}s")

        # Attempt request with retries
        for attempt in range(self.max_retries):
            try:
                response = await self._execute_request(
                    url, method, data, headers, params, attempt
                )

                # Cache successful responses
                if self.use_caching and use_cache and response.status_code < 500:
                    await self._cache_response(
                        url, method, response, params, data, headers
                    )

                return response

            except Exception as e:
                self.request_stats.errors += 1

                if attempt == self.max_retries - 1:
                    logger.error(
                        f"[{self.agent_name}] Request failed after {self.max_retries} "
                        f"attempts: {url} - {e}"
                    )
                    return None

                # Exponential backoff
                backoff_time = self._calculate_backoff(attempt)
                logger.warning(
                    f"[{self.agent_name}] Request failed (attempt {attempt + 1}/"
                    f"{self.max_retries}), retrying in {backoff_time:.1f}s: {e}"
                )
                await asyncio.sleep(backoff_time)

        return None

    async def _get_cached_response(
            self,
            url: str,
            method: str,
            params: Optional[Dict],
            data: Optional[Dict],
            headers: Optional[Dict]
    ) -> Optional[CachedResponse]:
        """Check cache for existing response."""
        cached = await self.cache.get(url, method, params, data, headers)
        if cached:
            self.request_stats.cached_responses += 1
            logger.debug(f"[{self.agent_name}] Cache hit: {url}")
            return CachedResponse(
                text=cached.response_text,
                status_code=cached.status_code,
                headers=cached.headers
            )
        return None

    async def _execute_request(
            self,
            url: str,
            method: str,
            data: Optional[Dict],
            headers: Optional[Dict],
            params: Optional[Dict],
            attempt: int
    ) -> httpx.Response:
        """Execute HTTP request and report metrics."""
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
            retry_after = self._extract_retry_after(response)
            await self.rate_limiter.report_response(
                url, response.status_code, response_time, retry_after
            )

        logger.debug(
            f"[{self.agent_name}] {method} {url} -> {response.status_code} "
            f"({response_time * 1000:.0f}ms)"
        )

        return response

    def _extract_retry_after(self, response: httpx.Response) -> Optional[int]:
        """Extract Retry-After header value."""
        retry_after_header = response.headers.get('Retry-After')
        if retry_after_header:
            try:
                return int(retry_after_header)
            except ValueError:
                logger.warning(f"Invalid Retry-After header: {retry_after_header}")
        return None

    async def _cache_response(
            self,
            url: str,
            method: str,
            response: httpx.Response,
            params: Optional[Dict],
            data: Optional[Dict],
            headers: Optional[Dict]
    ) -> None:
        """Store response in cache."""
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
        logger.debug(f"[{self.agent_name}] Cached response: {url}")

    def get_request_stats(self) -> Dict[str, Any]:
        """
        Get request statistics for this agent.

        Returns:
            Dictionary with request metrics including cache hit rate

        Example:
            stats = agent.get_request_stats()
            print(f"Total requests: {stats['total_requests']}")
            print(f"Cache hit rate: {stats['cache_hit_rate']:.1f}%")
        """
        return self.request_stats.to_dict()

    # ========================================================================
    # CVSS SCORING
    # ========================================================================

    def calculate_cvss_score(self, severity: Severity) -> float:
        """
        Calculate approximate CVSS score based on severity.

        Args:
            severity: Vulnerability severity level

        Returns:
            CVSS score (0.0 - 10.0)

        Example:
            score = self.calculate_cvss_score(Severity.HIGH)  # Returns 7.5
        """
        cvss_map = {
            Severity.CRITICAL: AgentConfig.CVSS_CRITICAL,
            Severity.HIGH: AgentConfig.CVSS_HIGH,
            Severity.MEDIUM: AgentConfig.CVSS_MEDIUM,
            Severity.LOW: AgentConfig.CVSS_LOW,
            Severity.INFO: AgentConfig.CVSS_INFO
        }
        return cvss_map.get(severity, 0.0)

    # ========================================================================
    # AI ANALYSIS
    # ========================================================================

    def _extract_json(self, text: str) -> Dict[str, Any]:
        """Extract JSON from potential markdown blocks."""
        try:
            # Try direct parse first
            return json.loads(text.strip())
        except json.JSONDecodeError:
            # Look for markdown code block
            match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1).strip())
                except:
                    pass
            
            # Simple fallback for standard JSON objects
            match = re.search(r'(\{.*\})', text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1).strip())
                except:
                    pass
        return {}

    async def analyze_with_ai(
            self,
            vulnerability_type: str,
            context: str,
            response_data: str
    ) -> Dict[str, Any]:
        """
        Use Groq LPU to analyze potential vulnerability.

        Args:
            vulnerability_type: Type of vulnerability being tested
            context: Context about the test (what was attempted)
            response_data: Response data to analyze

        Returns:
            AI analysis with confidence, likelihood, impact, etc.

        Raises:
            AIAnalysisException: If AI analysis fails
        """
        try:
            prompt = f"""
            Analyze this security finding and provide a structured assessment.
            
            Vulnerability Type: {vulnerability_type}
            Context: {context}
            Response Snippet (First 2000 chars): 
            ---
            {response_data[:2000] if response_data else 'No response data provided.'}
            ---
            
            Analyze the response to determine if it confirms the vulnerability.
            BE CRITICAL. If it looks like a generic error page or is not clearly exploitable, mark 'is_vulnerable': false.
            
            Return a JSON object with this exact structure:
            {{
                "is_vulnerable": boolean,
                "confidence": integer (0-100),
                "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO",
                "title": "Concise Technical Title",
                "description": "Detailed technical explanation of the finding",
                "reason": "Why you believe this is or is not a vulnerability",
                "remediation": "Brief high-level fix guidance",
                "likelihood": float (0.0-10.0),
                "impact": float (0.0-10.0),
                "exploitability_rationale": "Why this is easy or hard to exploit"
            }}
            """
            
            response = await scanner_generate(
                prompt=prompt, 
                json_mode=False,
                system_prompt="You are an expert security researcher. Extract vulnerabilities from raw HTTP data. Output ONLY raw JSON."
            )
            content = response.get("content", "{}")
            return self._extract_json(content)
            
        except Exception as e:
            logger.error(f"[{self.agent_name}] Groq analysis failed: {e}", exc_info=True)
            # Fallback to safe defaults rather than crashing
            return {
                "is_vulnerable": False, 
                "confidence": 0, 
                "severity": "INFO",
                "title": f"Scan Error: {vulnerability_type}",
                "description": f"AI analysis failed to process this finding: {str(e)}",
                "reason": "AI processing error",
                "remediation": "Manual verification required."
            }

    async def generate_remediation(
            self,
            vulnerability_type: str,
            code_context: str,
            technology_stack: List[str]
    ) -> Dict[str, Any]:
        """
        Generate detailed remediation recommendations using Groq.

        Args:
            vulnerability_type: Type of vulnerability
            code_context: Code or context where vulnerability exists
            technology_stack: Technologies used (e.g., ["PHP", "MySQL"])

        Returns:
            Remediation recommendations with code examples
        """
        try:
            prompt = f"""
            Provide detailed remediation for this vulnerability.
            
            Vulnerability: {vulnerability_type}
            Context: {code_context}
            Technologies: {', '.join(technology_stack) if technology_stack else 'Unknown'}
            
            Return a JSON object with:
            {{
                "remediation": "Step-by-step description",
                "remediation_code": "Corrected code snippet",
                "reference_links": ["list", "of", "links"],
                "best_practices": "Security best practices list"
            }}
            """
            
            response = await scanner_generate(
                prompt=prompt, 
                json_mode=False,
                system_prompt="You are a senior security engineer providing remediation guidance. Output ONLY raw JSON."
            )
            return self._extract_json(response.get("content", "{}"))
        except Exception as e:
            logger.error(f"[{self.agent_name}] Remediation generation failed: {e}")
            return {
                "remediation": "Standard remediation required.",
                "remediation_code": "",
                "reference_links": [],
                "best_practices": "Follow OWASP guidelines."
            }

    # ========================================================================
    # RESULT CREATION
    # ========================================================================

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
            **kwargs: Any
    ) -> AgentResult:
        """
        Create a standardized AgentResult.

        Args:
            vulnerability_type: Type of vulnerability detected
            is_vulnerable: Whether vulnerability was confirmed
            severity: Severity level
            confidence: Confidence score (0-100)
            url: Affected URL
            title: Short vulnerability title
            description: Detailed description
            likelihood: Likelihood score (0-10)
            impact: Impact score (0-10)
            exploitability_rationale: Explanation of exploitability
            **kwargs: Additional fields (evidence, remediation, etc.)

        Returns:
            AgentResult object

        Example:
            result = self.create_result(
                vulnerability_type=VulnerabilityType.XSS_REFLECTED,
                is_vulnerable=True,
                severity=Severity.HIGH,
                confidence=95.0,
                url="https://example.com/search",
                parameter="q",
                title="Reflected XSS in Search",
                description="User input is reflected without encoding",
                evidence="<script>alert(1)</script> appeared in response",
                remediation="Encode all user input before displaying"
            )
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
            **kwargs: Any
    ) -> AgentResult:
        """
        Create result from AI analysis dictionary.

        Extracts likelihood, impact, and exploitability from AI analysis
        and creates a properly formatted AgentResult.

        Args:
            ai_analysis: Dictionary from AI analysis
            vulnerability_type: Type of vulnerability
            url: Affected URL
            title: Vulnerability title
            description: Description
            severity: Severity level
            **kwargs: Additional fields

        Returns:
            AgentResult with AI analysis integrated

        Example:
            ai_analysis = await self.analyze_with_ai(...)
            result = self.create_result_from_ai(
                ai_analysis=ai_analysis,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                url="https://example.com/api/users",
                title="SQL Injection Detected",
                description="Time-based blind SQL injection",
                severity=Severity.CRITICAL
            )
        """
        # Extract and validate likelihood (0-10 scale)
        likelihood = self._extract_numeric_field(
            ai_analysis, "likelihood", default=0.0, max_value=10.0
        )

        # Extract and validate impact (0-10 scale)
        # Try impact_score first, then fall back to impact
        impact = self._extract_numeric_field(
            ai_analysis, "impact_score", default=None, max_value=10.0
        )
        if impact is None:
            impact = self._extract_numeric_field(
                ai_analysis, "impact", default=None, max_value=10.0
            )

        # If impact is still None or was a string, use severity-based default
        if impact is None:
            impact = AgentConfig.SEVERITY_IMPACT_MAP.get(severity, 5.0)

        # Extract exploitability rationale
        exploitability = (
                ai_analysis.get("exploitability_rationale", "") or
                ai_analysis.get("exploitability_conditions", "")
        )

        return self.create_result(
            vulnerability_type=vulnerability_type,
            is_vulnerable=ai_analysis.get("is_vulnerable", True),
            severity=severity,
            confidence=ai_analysis.get("confidence", 85.0),
            url=url,
            title=title,
            description=description,
            ai_analysis=ai_analysis.get("reason", ""),
            likelihood=likelihood,
            impact=impact,
            exploitability_rationale=exploitability,
            **kwargs
        )

    def _extract_numeric_field(
            self,
            data: Dict[str, Any],
            field: str,
            default: Optional[float],
            max_value: float = 10.0
    ) -> Optional[float]:
        """
        Safely extract numeric field from dictionary.

        Args:
            data: Dictionary to extract from
            field: Field name
            default: Default value if extraction fails
            max_value: Maximum allowed value

        Returns:
            Numeric value or default
        """
        value = data.get(field, default)
        if value is None:
            return default

        try:
            numeric_value = float(value)
            return min(numeric_value, max_value)
        except (ValueError, TypeError):
            logger.warning(
                f"[{self.agent_name}] Could not convert {field}='{value}' to float, "
                f"using default={default}"
            )
            return default

    # ========================================================================
    # EVIDENCE TRACKING
    # ========================================================================

    def create_evidence_chain(
            self,
            url: str,
            parameter: str,
            vuln_type: VulnerabilityType,
            detection_method: DetectionMethod
    ) -> EvidenceChain:
        """
        Create evidence chain for tracking vulnerability detection.

        Evidence chains track the sequence of requests/responses that
        prove a vulnerability exists.

        Args:
            url: Target URL
            parameter: Vulnerable parameter name
            vuln_type: Vulnerability type
            detection_method: Detection method used

        Returns:
            New evidence chain

        Example:
            chain = self.create_evidence_chain(
                url="https://example.com/api/user",
                parameter="id",
                vuln_type=VulnerabilityType.SQL_INJECTION,
                detection_method=DetectionMethod.TIME_BASED
            )
        """
        chain_id = self.evidence_tracker.generate_chain_id(
            url, parameter or "", vuln_type.value
        )
        chain = self.evidence_tracker.create_chain(chain_id, detection_method)
        logger.debug(f"[{self.agent_name}] Created evidence chain: {chain_id}")
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
            request: Request data (url, method, params, etc.)
            response_text: Response content
            response_time_ms: Response time in milliseconds
            status_code: HTTP status code
            note: Optional note about this interaction

        Example:
            self.add_evidence(
                chain=chain,
                request={"url": url, "method": "GET", "params": params},
                response_text=response.text,
                response_time_ms=150.5,
                status_code=200,
                note="Baseline request"
            )
        """
        # Truncate large responses
        truncated_response = response_text[:AgentConfig.MAX_CACHED_RESPONSE_SIZE]

        chain.add_interaction(
            request=request,
            response={"text": truncated_response},
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

        The baseline represents the normal/expected response that will
        be compared against exploitation attempts.

        Args:
            chain: Evidence chain
            request: Request data
            response_text: Response content
            response_time_ms: Response time
            status_code: HTTP status code

        Example:
            self.set_baseline(
                chain=chain,
                request={"url": url, "method": "GET"},
                response_text=normal_response.text,
                response_time_ms=120.0,
                status_code=200
            )
        """
        truncated_response = response_text[:AgentConfig.MAX_CACHED_RESPONSE_SIZE]

        chain.set_baseline(
            request=request,
            response={"text": truncated_response},
            response_time_ms=response_time_ms,
            status_code=status_code
        )
        logger.debug(f"[{self.agent_name}] Set baseline for chain {chain.chain_id}")

    # ========================================================================
    # RESPONSE COMPARISON
    # ========================================================================

    def compare_responses(
            self,
            baseline_response: str,
            test_response: str,
            normalize: bool = True
    ) -> ResponseDiff:
        """
        Compare two responses to detect significant changes.

        Useful for blind vulnerability detection where responses have
        subtle differences (e.g., error-based SQL injection, timing attacks).

        Args:
            baseline_response: Original/normal response
            test_response: Response after exploitation attempt
            normalize: Whether to normalize responses (remove whitespace, etc.)

        Returns:
            ResponseDiff with detailed comparison

        Example:
            diff = self.compare_responses(
                baseline_response=normal_resp.text,
                test_response=exploit_resp.text,
                normalize=True
            )

            if diff.similarity < 0.9:  # Significant difference
                print(f"Detected change: {diff.added_content}")
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

        Used for blind SQL injection, blind command injection, etc.
        Compares responses when condition is TRUE vs FALSE.

        Args:
            baseline: Normal response
            true_response: Response when condition is TRUE
            false_response: Response when condition is FALSE

        Returns:
            Analysis of boolean behavior with confidence score

        Example:
            analysis = self.detect_boolean_based(
                baseline=normal_response,
                true_response=sqli_true_response,  # 1=1
                false_response=sqli_false_response  # 1=2
            )

            if analysis['is_boolean_based']:
                print(f"Detected blind SQLi with {analysis['confidence']}% confidence")
        """
        return self.diff_detector.detect_boolean_based(
            baseline, true_response, false_response
        )