"""
CSRF Agent - Detects Cross-Site Request Forgery vulnerabilities.
"""
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType


class CSRFAgent(BaseSecurityAgent):
    """
    CSRF vulnerability detection agent.
    
    Tests for:
    - Missing CSRF tokens on state-changing endpoints
    - Predictable/weak CSRF tokens
    - Token validation bypass
    - SameSite cookie misconfiguration
    """
    
    agent_name = "csrf"
    agent_description = "Tests for Cross-Site Request Forgery vulnerabilities"
    vulnerability_types = [VulnerabilityType.CSRF]
    
    # Common CSRF token field names
    TOKEN_FIELD_NAMES = [
        "csrf", "csrf_token", "csrftoken", "_csrf", "csrf-token",
        "xsrf", "xsrf_token", "xsrftoken", "_xsrf", "xsrf-token",
        "authenticity_token", "_token", "token", "nonce",
        "__RequestVerificationToken", "anticsrf", "anti-csrf"
    ]
    
    # Common CSRF header names
    TOKEN_HEADER_NAMES = [
        "X-CSRF-Token", "X-XSRF-Token", "X-CSRFToken",
        "X-Requested-With"
    ]
    
    async def scan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str] = None,
        scan_context: Optional[Any] = None
    ) -> List[AgentResult]:
        """
        Scan for CSRF vulnerabilities.
        
        Args:
            target_url: Base URL
            endpoints: Endpoints to test
            technology_stack: Detected technologies
            
        Returns:
            List of found vulnerabilities
        """
        results = []
        
        # Filter for state-changing methods
        state_changing_endpoints = [
            ep for ep in endpoints 
            if ep.get("method", "GET").upper() in ["POST", "PUT", "DELETE", "PATCH"]
        ]
        
        for endpoint in state_changing_endpoints:
            url = endpoint.get("url", target_url)
            method = endpoint.get("method", "POST").upper()
            
            # Check for CSRF protection
            csrf_result = await self._test_csrf_protection(url, method, endpoint)
            if csrf_result:
                results.append(csrf_result)
        
        # Check SameSite cookie attribute
        cookie_result = await self._check_samesite_cookies(target_url)
        if cookie_result:
            results.append(cookie_result)
        
        return results
    
    async def _test_csrf_protection(
        self,
        url: str,
        method: str,
        endpoint: Dict[str, Any]
    ) -> Optional[AgentResult]:
        """
        Test if endpoint has proper CSRF protection.
        
        Args:
            url: Endpoint URL
            method: HTTP method
            endpoint: Endpoint details
            
        Returns:
            AgentResult if vulnerable
        """
        try:
            # First, get the page to check for CSRF tokens
            page_response = await self.make_request(url, method="GET")
            if not page_response:
                return None
            
            page_content = page_response.text
            
            # Check for CSRF token in HTML
            token_in_html = self._find_csrf_token_in_html(page_content)
            
            # Check for CSRF token in cookies
            token_in_cookies = self._find_csrf_token_in_cookies(page_response)
            
            # Check for required headers
            requires_custom_header = self._requires_custom_header(page_response)
            
            # If no CSRF protection found, test if state-changing request succeeds
            if not token_in_html and not token_in_cookies and not requires_custom_header:
                # Try to make a state-changing request without token
                test_data = endpoint.get("params", {})
                if not test_data:
                    test_data = {"test": "csrf_test"}
                
                response = await self.make_request(
                    url,
                    method=method,
                    data=test_data,
                    headers={"Origin": "https://evil.attacker.com"}
                )
                
                if response and response.status_code in [200, 201, 302, 303]:
                    # Request succeeded without CSRF token - vulnerable!
                    return self.create_result(
                        vulnerability_type=VulnerabilityType.CSRF,
                        is_vulnerable=True,
                        severity=Severity.HIGH,
                        confidence=85,
                        url=url,
                        method=method,
                        title=f"Missing CSRF Protection on {method} Endpoint",
                        description=(
                            f"The {method} endpoint at {url} does not implement CSRF protection. "
                            "An attacker could craft a malicious page that submits unauthorized "
                            "requests on behalf of authenticated users."
                        ),
                        evidence=f"No CSRF token found. {method} request from foreign origin succeeded with status {response.status_code}",
                        likelihood=7.0,
                        impact=7.0,
                        exploitability_rationale=(
                            "Directly exploitable. Attacker can host malicious HTML that auto-submits "
                            "forms to this endpoint. Requires victim to be authenticated and visit attacker's page."
                        ),
                        remediation=(
                            "Implement CSRF tokens:\n"
                            "1. Generate cryptographically random tokens per session/request\n"
                            "2. Include token in forms as hidden field or custom header\n"
                            "3. Validate token server-side before processing request\n"
                            "4. Use SameSite=Strict or Lax cookie attribute"
                        ),
                        owasp_category="A01:2021 – Broken Access Control",
                        cwe_id="CWE-352"
                    )
            
            # Check for weak/predictable token
            if token_in_html:
                weakness = self._analyze_token_strength(token_in_html)
                if weakness:
                    return self.create_result(
                        vulnerability_type=VulnerabilityType.CSRF,
                        is_vulnerable=True,
                        severity=Severity.MEDIUM,
                        confidence=70,
                        url=url,
                        title="Weak CSRF Token",
                        description=f"CSRF token appears to be {weakness}",
                        evidence=f"Token: {token_in_html[:20]}... - {weakness}",
                        likelihood=5.0,
                        impact=7.0,
                        exploitability_rationale=(
                            "Conditionally exploitable. Weak token may be predictable or brute-forceable, "
                            "but requires additional analysis to confirm."
                        ),
                        remediation="Use cryptographically secure random tokens (min 128 bits entropy)",
                        owasp_category="A01:2021 – Broken Access Control",
                        cwe_id="CWE-352"
                    )
            
        except Exception as e:
            print(f"[CSRF Agent] Error testing {url}: {e}")
        
        return None
    
    def _find_csrf_token_in_html(self, html: str) -> Optional[str]:
        """Find CSRF token in HTML content."""
        html_lower = html.lower()
        
        for field_name in self.TOKEN_FIELD_NAMES:
            # Check hidden input fields
            pattern = rf'<input[^>]*name=["\']?{field_name}["\']?[^>]*value=["\']?([^"\'>\s]+)'
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
            
            # Check meta tags
            pattern = rf'<meta[^>]*name=["\']?{field_name}["\']?[^>]*content=["\']?([^"\'>\s]+)'
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _find_csrf_token_in_cookies(self, response) -> Optional[str]:
        """Find CSRF token in cookies."""
        cookies = response.headers.get("set-cookie", "")
        
        for token_name in self.TOKEN_FIELD_NAMES:
            if token_name.lower() in cookies.lower():
                return token_name
        
        return None
    
    def _requires_custom_header(self, response) -> bool:
        """Check if endpoint requires custom header (implicit CSRF protection)."""
        # Some APIs require X-Requested-With header which provides implicit protection
        # Check CORS headers to see if custom headers are expected
        cors_headers = response.headers.get("Access-Control-Allow-Headers", "")
        return "x-requested-with" in cors_headers.lower()
    
    def _analyze_token_strength(self, token: str) -> Optional[str]:
        """Analyze CSRF token for weaknesses."""
        if not token:
            return None
        
        # Check length
        if len(token) < 16:
            return "too short (less than 16 characters)"
        
        # Check for sequential patterns
        if token.isdigit():
            return "numeric only (potentially sequential)"
        
        # Check for timestamp-based tokens
        if re.match(r'^\d{10,13}', token):
            return "appears to be timestamp-based"
        
        # Check for low entropy
        unique_chars = len(set(token))
        if unique_chars < len(token) / 4:
            return "low entropy (few unique characters)"
        
        return None
    
    async def _check_samesite_cookies(self, url: str) -> Optional[AgentResult]:
        """Check if session cookies have SameSite attribute."""
        try:
            response = await self.make_request(url)
            if not response:
                return None
            
            set_cookie = response.headers.get("set-cookie", "")
            
            # Look for session cookies without SameSite
            session_patterns = ["session", "sess", "sid", "auth", "token"]
            
            for pattern in session_patterns:
                if pattern in set_cookie.lower():
                    if "samesite" not in set_cookie.lower():
                        return self.create_result(
                            vulnerability_type=VulnerabilityType.CSRF,
                            is_vulnerable=True,
                            severity=Severity.LOW,
                            confidence=90,
                            url=url,
                            title="Session Cookie Missing SameSite Attribute",
                            description=(
                                "Session cookies are set without the SameSite attribute, "
                                "which provides defense-in-depth against CSRF attacks."
                            ),
                            evidence=f"Set-Cookie header lacks SameSite attribute",
                            likelihood=3.0,
                            impact=5.0,
                            exploitability_rationale=(
                                "Not directly exploitable alone. Missing SameSite increases "
                                "CSRF attack surface but requires additional CSRF vulnerabilities."
                            ),
                            remediation="Add SameSite=Lax or SameSite=Strict to session cookies",
                            owasp_category="A05:2021 – Security Misconfiguration",
                            cwe_id="CWE-1275"
                        )
                    break
        
        except Exception as e:
            print(f"[CSRF Agent] Cookie check error: {e}")
        
        return None
