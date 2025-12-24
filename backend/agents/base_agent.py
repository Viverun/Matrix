"""
Base Security Agent - Abstract base class for all security testing agents.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import httpx
import asyncio
from datetime import datetime

from core.groq_client import gemini_client
from models.vulnerability import Severity, VulnerabilityType


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
    
    def __init__(self, timeout: float = 30.0, max_retries: int = 3):
        """
        Initialize the security agent.
        
        Args:
            timeout: HTTP request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.results: List[AgentResult] = []
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False  # Allow self-signed certs for testing
        )
        self.gemini = gemini_client
    
    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()
    
    @abstractmethod
    async def scan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str] = None
    ) -> List[AgentResult]:
        """
        Perform security scan on target.
        
        Args:
            target_url: Base URL of the target application
            endpoints: List of discovered endpoints to test
            technology_stack: Detected technology stack
            
        Returns:
            List of AgentResult objects for any vulnerabilities found
        """
        pass
    
    async def make_request(
        self,
        url: str,
        method: str = "GET",
        data: Dict = None,
        headers: Dict = None,
        params: Dict = None
    ) -> Optional[httpx.Response]:
        """
        Make an HTTP request with retry logic.
        
        Args:
            url: Target URL
            method: HTTP method
            data: POST/PUT body data
            headers: Request headers
            params: Query parameters
            
        Returns:
            Response object or None if all retries failed
        """
        for attempt in range(self.max_retries):
            try:
                response = await self.http_client.request(
                    method=method,
                    url=url,
                    data=data,
                    headers=headers,
                    params=params
                )
                return response
            except Exception as e:
                if attempt == self.max_retries - 1:
                    print(f"[{self.agent_name}] Request failed after {self.max_retries} attempts: {e}")
                    return None
                await asyncio.sleep(1)  # Wait before retry
        
        return None
    
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
            **kwargs
        )
