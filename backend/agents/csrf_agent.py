"""
CSRF Agent - Detects Cross-Site Request Forgery vulnerabilities.

This agent performs comprehensive CSRF testing including:
- Missing CSRF tokens on state-changing endpoints
- Weak/predictable CSRF tokens
- Token validation bypass techniques
- SameSite cookie misconfiguration
- CORS misconfiguration enabling CSRF
- Token reuse vulnerabilities
- Double-submit cookie pattern weaknesses
"""
import re
import math
import hashlib
import logging
import asyncio
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass
from enum import Enum

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType

# Configure logging
logger = logging.getLogger(__name__)


class CSRFProtectionType(Enum):
    """Types of CSRF protection mechanisms."""
    NONE = "none"
    SYNCHRONIZER_TOKEN = "synchronizer_token"
    DOUBLE_SUBMIT_COOKIE = "double_submit_cookie"
    CUSTOM_HEADER = "custom_header"
    SAMESITE_COOKIE = "samesite_cookie"
    REFERER_VALIDATION = "referer_validation"


@dataclass
class CSRFTokenInfo:
    """Information about a detected CSRF token."""
    value: str
    location: str  # 'html', 'cookie', 'header'
    field_name: str
    entropy: float
    length: int
    is_weak: bool
    weakness_reason: Optional[str] = None


class CSRFConfig:
    """Configuration constants for CSRF agent."""

    # Timeouts
    REQUEST_TIMEOUT = 15
    REQUEST_DELAY = 0.5  # Delay between requests to avoid rate limiting

    # Token analysis
    MIN_TOKEN_LENGTH = 16
    MIN_TOKEN_ENTROPY = 3.0  # bits per character
    WEAK_ENTROPY_THRESHOLD = 2.5

    # Testing
    MAX_BYPASS_ATTEMPTS = 5
    TOKEN_REUSE_TEST_COUNT = 3

    # Test domains (RFC 2606 compliant test domains)
    TEST_ORIGIN = "https://attacker.example"
    TEST_REFERER = "https://attacker.example/csrf-poc.html"

    # Common CSRF token field names
    TOKEN_FIELD_NAMES = [
        "csrf", "csrf_token", "csrftoken", "_csrf", "csrf-token",
        "xsrf", "xsrf_token", "xsrftoken", "_xsrf", "xsrf-token",
        "authenticity_token", "_token", "token", "nonce",
        "__RequestVerificationToken", "anticsrf", "anti-csrf",
        "csrfmiddlewaretoken", "csrfKey", "csrf_value"
    ]

    # Common CSRF header names
    TOKEN_HEADER_NAMES = [
        "X-CSRF-Token", "X-XSRF-Token", "X-CSRFToken",
        "X-Requested-With", "X-CSRF-Header", "X-XSRF-Header"
    ]

    # Session cookie patterns
    SESSION_COOKIE_PATTERNS = [
        "session", "sess", "sid", "sessionid", "jsessionid",
        "phpsessid", "asp.net_sessionid", "auth", "token",
        "access_token", "jwt", "bearer"
    ]

    # State-changing methods
    STATE_CHANGING_METHODS = ["POST", "PUT", "DELETE", "PATCH"]

    # Safe HTTP status codes (request was processed)
    SUCCESS_STATUS_CODES = [200, 201, 202, 204, 301, 302, 303, 307, 308]


class CSRFAgent(BaseSecurityAgent):
    """
    CSRF vulnerability detection agent with comprehensive testing capabilities.

    Detection Features:
    - Missing CSRF protection on state-changing endpoints
    - Weak/predictable token generation
    - Token validation bypass techniques
    - Token reuse across sessions
    - SameSite cookie misconfiguration
    - CORS misconfiguration enabling CSRF
    - Double-submit cookie weaknesses
    - Referer/Origin header bypass

    Testing Methodology:
    1. Identify state-changing endpoints
    2. Analyze existing CSRF protection mechanisms
    3. Test token bypass techniques
    4. Evaluate token strength and entropy
    5. Check defense-in-depth measures (SameSite, CORS)
    6. Correlate findings for comprehensive assessment
    """

    agent_name = "csrf"
    agent_description = "Tests for Cross-Site Request Forgery vulnerabilities"
    vulnerability_types = [VulnerabilityType.CSRF]

    def __init__(self):
        """Initialize CSRF agent with tracking collections."""
        super().__init__()
        self._tested_endpoints: Set[str] = set()
        self._discovered_tokens: Dict[str, CSRFTokenInfo] = {}
        self._session_cookies: Dict[str, str] = {}

    async def scan(
            self,
            target_url: str,
            endpoints: List[Dict[str, Any]],
            technology_stack: Optional[List[str]] = None,
            scan_context: Optional[Any] = None
    ) -> List[AgentResult]:
        """
        Scan for CSRF vulnerabilities across all state-changing endpoints.

        Args:
            target_url: Base URL of the target application
            endpoints: List of discovered endpoints to test
            technology_stack: Detected technologies (used for framework-specific checks)
            scan_context: Shared context for cross-agent intelligence

        Returns:
            List of discovered CSRF vulnerabilities with detailed evidence
        """
        logger.info(f"Starting CSRF scan on {target_url} with {len(endpoints)} endpoints")
        results: List[AgentResult] = []

        # Filter for state-changing methods
        state_changing_endpoints = self._filter_state_changing_endpoints(endpoints)
        logger.debug(f"Found {len(state_changing_endpoints)} state-changing endpoints")

        if not state_changing_endpoints:
            logger.warning("No state-changing endpoints found to test")
            return results

        # Phase 1: Test individual endpoints for CSRF protection
        for endpoint in state_changing_endpoints:
            endpoint_results = await self._test_endpoint_csrf(
                endpoint,
                target_url,
                technology_stack
            )
            results.extend(endpoint_results)
            # Add delay to avoid rate limiting
            await asyncio.sleep(CSRFConfig.REQUEST_DELAY)

        # Phase 2: Check application-wide protections
        global_results = await self._check_global_protections(target_url)
        results.extend(global_results)

        # Phase 3: Test token reuse if tokens were found
        if self._discovered_tokens:
            reuse_results = await self._test_token_reuse(target_url)
            results.extend(reuse_results)

        logger.info(f"CSRF scan completed. Found {len(results)} vulnerabilities")
        return results

    def _filter_state_changing_endpoints(
            self,
            endpoints: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Filter endpoints to only include state-changing HTTP methods."""
        return [
            ep for ep in endpoints
            if ep.get("method", "GET").upper() in CSRFConfig.STATE_CHANGING_METHODS
        ]

    async def _test_endpoint_csrf(
            self,
            endpoint: Dict[str, Any],
            target_url: str,
            technology_stack: Optional[List[str]] = None
    ) -> List[AgentResult]:
        """Comprehensive CSRF testing for a single endpoint."""
        results: List[AgentResult] = []
        url = endpoint.get("url", target_url)
        method = endpoint.get("method", "POST").upper()

        endpoint_key = f"{method}:{url}"
        if endpoint_key in self._tested_endpoints:
            return results

        self._tested_endpoints.add(endpoint_key)
        logger.debug(f"Testing CSRF on {method} {url}")

        try:
            protection_analysis = await self._analyze_csrf_protection(url, method, endpoint)

            if protection_analysis["type"] == CSRFProtectionType.NONE:
                bypass_result = await self._test_missing_protection(
                    url, method, endpoint, protection_analysis
                )
                if bypass_result:
                    results.append(bypass_result)

            elif protection_analysis["type"] == CSRFProtectionType.SYNCHRONIZER_TOKEN:
                bypass_results = await self._test_token_bypass(
                    url, method, endpoint, protection_analysis
                )
                results.extend(bypass_results)

                if protection_analysis.get("token_info"):
                    token_weakness = await self._test_token_strength(
                        url, method, protection_analysis["token_info"]
                    )
                    if token_weakness:
                        results.append(token_weakness)

            elif protection_analysis["type"] == CSRFProtectionType.DOUBLE_SUBMIT_COOKIE:
                double_submit_result = await self._test_double_submit_weakness(
                    url, method, endpoint, protection_analysis
                )
                if double_submit_result:
                    results.append(double_submit_result)

            origin_result = await self._test_origin_referer_bypass(url, method, endpoint)
            if origin_result:
                results.append(origin_result)

        except Exception as e:
            logger.error(f"Error testing CSRF on {method} {url}: {e}", exc_info=True)

        return results

    async def _analyze_csrf_protection(
            self,
            url: str,
            method: str,
            endpoint: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze what CSRF protection mechanisms are in place."""
        try:
            response = await self.make_request(url, method="GET")
            if not response:
                return {"type": CSRFProtectionType.NONE}

            token_info = self._find_csrf_token(response)
            if token_info:
                self._discovered_tokens[url] = token_info
                return {
                    "type": CSRFProtectionType.SYNCHRONIZER_TOKEN,
                    "token_info": token_info,
                    "response": response
                }

            if self._has_double_submit_cookie(response):
                return {
                    "type": CSRFProtectionType.DOUBLE_SUBMIT_COOKIE,
                    "response": response
                }

            if self._requires_custom_header(response):
                return {
                    "type": CSRFProtectionType.CUSTOM_HEADER,
                    "response": response
                }

            if self._has_samesite_strict(response):
                return {
                    "type": CSRFProtectionType.SAMESITE_COOKIE,
                    "response": response
                }

            return {"type": CSRFProtectionType.NONE, "response": response}

        except Exception as e:
            logger.error(f"Error analyzing CSRF protection for {url}: {e}")
            return {"type": CSRFProtectionType.NONE}

    def _find_csrf_token(self, response) -> Optional[CSRFTokenInfo]:
        """Search for CSRF tokens in HTML, cookies, and headers."""
        if not response:
            return None

        if hasattr(response, 'text'):
            token_from_html = self._find_token_in_html(response.text)
            if token_from_html:
                return token_from_html

        token_from_cookie = self._find_token_in_cookies(response)
        if token_from_cookie:
            return token_from_cookie

        token_from_header = self._find_token_in_headers(response)
        if token_from_header:
            return token_from_header

        return None

    def _find_token_in_html(self, html: str) -> Optional[CSRFTokenInfo]:
        """Extract CSRF token from HTML content."""
        if not html:
            return None

        for field_name in CSRFConfig.TOKEN_FIELD_NAMES:
            patterns = [
                rf'<input[^>]*name=["\']?{field_name}["\']?[^>]*value=["\']?([^"\'>\s]+)',
                rf'<input[^>]*value=["\']?([^"\'>\s]+)[^>]*name=["\']?{field_name}["\']?'
            ]

            for pattern in patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    token_value = match.group(1)
                    return CSRFTokenInfo(
                        value=token_value,
                        location="html",
                        field_name=field_name,
                        entropy=self._calculate_entropy(token_value),
                        length=len(token_value),
                        is_weak=False
                    )

            patterns = [
                rf'<meta[^>]*name=["\']?{field_name}["\']?[^>]*content=["\']?([^"\'>\s]+)',
                rf'<meta[^>]*content=["\']?([^"\'>\s]+)[^>]*name=["\']?{field_name}["\']?'
            ]

            for pattern in patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    token_value = match.group(1)
                    return CSRFTokenInfo(
                        value=token_value,
                        location="html_meta",
                        field_name=field_name,
                        entropy=self._calculate_entropy(token_value),
                        length=len(token_value),
                        is_weak=False
                    )

        return None

    def _find_token_in_cookies(self, response) -> Optional[CSRFTokenInfo]:
        """Extract CSRF token from response cookies."""
        if not response or not hasattr(response, 'headers'):
            return None

        set_cookies = []
        if hasattr(response.headers, 'get_list'):
            set_cookies = response.headers.get_list("set-cookie")
        else:
            set_cookie = response.headers.get("set-cookie", "")
            if set_cookie:
                set_cookies = [set_cookie]

        for set_cookie in set_cookies:
            for token_name in CSRFConfig.TOKEN_FIELD_NAMES:
                pattern = rf'{token_name}=([^;]+)'
                match = re.search(pattern, set_cookie, re.IGNORECASE)
                if match:
                    token_value = match.group(1)
                    return CSRFTokenInfo(
                        value=token_value,
                        location="cookie",
                        field_name=token_name,
                        entropy=self._calculate_entropy(token_value),
                        length=len(token_value),
                        is_weak=False
                    )

        return None

    def _find_token_in_headers(self, response) -> Optional[CSRFTokenInfo]:
        """Extract CSRF token from response headers."""
        if not response or not hasattr(response, 'headers'):
            return None

        for header_name in CSRFConfig.TOKEN_HEADER_NAMES:
            token_value = response.headers.get(header_name)
            if token_value:
                return CSRFTokenInfo(
                    value=token_value,
                    location="header",
                    field_name=header_name,
                    entropy=self._calculate_entropy(token_value),
                    length=len(token_value),
                    is_weak=False
                )

        return None

    def _calculate_entropy(self, token: str) -> float:
        """Calculate Shannon entropy of a token."""
        if not token:
            return 0.0

        freq_dict = {}
        for char in token:
            freq_dict[char] = freq_dict.get(char, 0) + 1

        entropy = 0.0
        token_len = len(token)

        for count in freq_dict.values():
            probability = count / token_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _has_double_submit_cookie(self, response) -> bool:
        """Check if double-submit cookie pattern is used."""
        if not response or not hasattr(response, 'headers') or not hasattr(response, 'text'):
            return False

        set_cookies = []
        if hasattr(response.headers, 'get_list'):
            set_cookies = response.headers.get_list("set-cookie")
        else:
            set_cookie = response.headers.get("set-cookie", "")
            if set_cookie:
                set_cookies = [set_cookie]

        set_cookie_str = " ".join(set_cookies)

        for token_name in CSRFConfig.TOKEN_FIELD_NAMES:
            if token_name.lower() in set_cookie_str.lower():
                if token_name.lower() in response.text.lower():
                    return True

        return False

    def _requires_custom_header(self, response) -> bool:
        """Check if endpoint requires custom header."""
        if not response or not hasattr(response, 'headers'):
            return False

        cors_headers = response.headers.get("Access-Control-Allow-Headers", "")
        return any(
            header.lower() in cors_headers.lower()
            for header in CSRFConfig.TOKEN_HEADER_NAMES
        )

    def _has_samesite_strict(self, response) -> bool:
        """Check if session cookies have SameSite=Strict."""
        if not response or not hasattr(response, 'headers'):
            return False

        set_cookies = []
        if hasattr(response.headers, 'get_list'):
            set_cookies = response.headers.get_list("set-cookie")
        else:
            set_cookie = response.headers.get("set-cookie", "")
            if set_cookie:
                set_cookies = [set_cookie]

        set_cookie_str = " ".join(set_cookies)

        for pattern in CSRFConfig.SESSION_COOKIE_PATTERNS:
            if pattern in set_cookie_str.lower():
                if "samesite=strict" in set_cookie_str.lower():
                    return True

        return False

    async def _test_missing_protection(
            self,
            url: str,
            method: str,
            endpoint: Dict[str, Any],
            protection_analysis: Dict[str, Any]
    ) -> Optional[AgentResult]:
        """Test if requests succeed without any CSRF protection."""
        try:
            test_data = endpoint.get("params", {})
            if not test_data:
                test_data = {"test_field": "csrf_test_value"}

            response = await self.make_request(
                url,
                method=method,
                data=test_data,
                headers={
                    "Origin": CSRFConfig.TEST_ORIGIN,
                    "Referer": CSRFConfig.TEST_REFERER
                }
            )

            if response and response.status_code in CSRFConfig.SUCCESS_STATUS_CODES:
                evidence_parts = [
                    f"{method} request from foreign origin ({CSRFConfig.TEST_ORIGIN}) succeeded",
                    f"Response status: {response.status_code}",
                    "No CSRF token required",
                    "No origin/referer validation detected"
                ]

                state_changed = self._detect_state_change(response)
                if state_changed:
                    evidence_parts.append("State change confirmed in response")

                return self.create_result(
                    vulnerability_type=VulnerabilityType.CSRF,
                    is_vulnerable=True,
                    severity=Severity.HIGH,
                    confidence=90,
                    url=url,
                    method=method,
                    title=f"Missing CSRF Protection on {method} Endpoint",
                    description=(
                        f"The {method} endpoint at {url} does not implement any CSRF protection. "
                        "An attacker can craft a malicious webpage that automatically submits "
                        "unauthorized requests on behalf of authenticated users who visit the page."
                    ),
                    evidence="\n".join(evidence_parts),
                    likelihood=8.0,
                    impact=8.0,
                    exploitability_rationale=(
                        "DIRECTLY EXPLOITABLE: Attack complexity LOW, requires only victim authentication"
                    ),
                    remediation=(
                        "1. Implement synchronizer token pattern\n"
                        "2. Set SameSite=Strict or Lax on session cookies\n"
                        "3. Validate Origin and Referer headers"
                    ),
                    owasp_category="A01:2021 – Broken Access Control",
                    cwe_id="CWE-352"
                )

        except Exception as e:
            logger.error(f"Error testing missing protection on {url}: {e}")

        return None

    def _detect_state_change(self, response) -> bool:
        """Detect if response indicates state was changed."""
        if not response:
            return False

        if response.status_code in [301, 302, 303, 307, 308]:
            return True

        if not hasattr(response, 'text'):
            return False

        response_text = response.text.lower()

        indicators = [
            r'\bsuccessfully\s+(created|updated|deleted|saved|modified)',
            r'\bhas\s+been\s+(created|updated|deleted|saved|modified)',
            r'\bwas\s+(created|updated|deleted|saved|modified)',
            r'"status"\s*:\s*"success"',
            r'"success"\s*:\s*true',
        ]

        return any(re.search(pattern, response_text) for pattern in indicators)

    async def _test_token_bypass(
            self,
            url: str,
            method: str,
            endpoint: Dict[str, Any],
            protection_analysis: Dict[str, Any]
    ) -> List[AgentResult]:
        """Test various token bypass techniques."""
        results: List[AgentResult] = []
        token_info = protection_analysis.get("token_info")

        if not token_info:
            return results

        test_data = endpoint.get("params", {}).copy()
        if not test_data:
            test_data = {"test": "value"}

        bypass_techniques = [
            ("missing_token", None, "Request without token parameter"),
            ("empty_token", "", "Request with empty token value"),
            ("wrong_token", "invalid_token_12345", "Request with invalid token"),
            ("manipulated_token", token_info.value[::-1], "Request with manipulated token")
        ]

        for technique_name, token_value, description in bypass_techniques:
            try:
                request_data = test_data.copy()

                if token_value is not None:
                    request_data[token_info.field_name] = token_value

                response = await self.make_request(
                    url,
                    method=method,
                    data=request_data
                )

                if response and response.status_code in CSRFConfig.SUCCESS_STATUS_CODES:
                    redacted_value = f"{token_value[:8]}..." if token_value and len(token_value) > 8 else "[redacted]"

                    results.append(
                        self.create_result(
                            vulnerability_type=VulnerabilityType.CSRF,
                            is_vulnerable=True,
                            severity=Severity.HIGH,
                            confidence=95,
                            url=url,
                            method=method,
                            title=f"CSRF Token Validation Bypass - {technique_name.replace('_', ' ').title()}",
                            description=(
                                f"The endpoint accepts requests when the CSRF token is {technique_name.replace('_', ' ')}."
                            ),
                            evidence=(
                                f"{description}\n"
                                f"Response status: {response.status_code}\n"
                                f"Token field: {token_info.field_name}\n"
                                f"Test value: {redacted_value if token_value else '[not included]'}"
                            ),
                            likelihood=8.0,
                            impact=8.0,
                            exploitability_rationale="Token validation can be bypassed",
                            remediation="Fix token validation logic",
                            owasp_category="A01:2021 – Broken Access Control",
                            cwe_id="CWE-352"
                        )
                    )
                    break

                await asyncio.sleep(CSRFConfig.REQUEST_DELAY)

            except Exception as e:
                logger.debug(f"Token bypass test '{technique_name}' failed: {e}")

        return results

    async def _test_token_strength(
            self,
            url: str,
            method: str,
            token_info: CSRFTokenInfo
    ) -> Optional[AgentResult]:
        """Analyze CSRF token for cryptographic weaknesses."""
        weaknesses = []

        if token_info.length < CSRFConfig.MIN_TOKEN_LENGTH:
            weaknesses.append(f"Too short ({token_info.length} chars)")

        if token_info.entropy < CSRFConfig.WEAK_ENTROPY_THRESHOLD:
            weaknesses.append(f"Low entropy ({token_info.entropy:.2f} bits/char)")

        pattern_issues = self._detect_token_patterns(token_info.value)
        weaknesses.extend(pattern_issues)

        if weaknesses:
            token_sample = f"{token_info.value[:8]}...{token_info.value[-4:]}" if len(
                token_info.value) > 12 else "[redacted]"

            return self.create_result(
                vulnerability_type=VulnerabilityType.CSRF,
                is_vulnerable=True,
                severity=Severity.MEDIUM,
                confidence=75,
                url=url,
                method=method,
                title="Weak CSRF Token Generation",
                description="The CSRF token does not meet cryptographic strength requirements.",
                evidence=(
                        f"Token weaknesses:\n" +
                        "\n".join(f"- {w}" for w in weaknesses) +
                        f"\n\nToken sample: {token_sample}" +
                        f"\nLength: {token_info.length} characters" +
                        f"\nEntropy: {token_info.entropy:.2f} bits/character"
                ),
                likelihood=5.0,
                impact=7.0,
                exploitability_rationale="Weak token may enable prediction attacks",
                remediation="Use cryptographically secure random tokens (min 128 bits)",
                owasp_category="A02:2021 – Cryptographic Failures",
                cwe_id="CWE-330"
            )

        return None

    def _detect_token_patterns(self, token: str) -> List[str]:
        """Detect problematic patterns in token."""
        issues = []

        if token.isdigit():
            issues.append("Numeric only (potentially sequential)")

        if re.match(r'^\d{10,13}', token):
            issues.append("Appears to be timestamp-based")

        unique_chars = len(set(token))
        if unique_chars < len(token) / 4:
            issues.append(f"Low character diversity ({unique_chars}/{len(token)})")

        if self._has_sequential_pattern(token):
            issues.append("Contains sequential patterns")

        if len(token) == 32 and all(c in '0123456789abcdef' for c in token.lower()):
            issues.append("Appears to be MD5 hash (weak)")

        return issues

    def _has_sequential_pattern(self, token: str) -> bool:
        """Check for sequential character patterns in token."""
        if len(token) < 3:
            return False

        sequential_count = 0
        for i in range(len(token) - 2):
            if (ord(token[i]) + 1 == ord(token[i + 1]) and
                    ord(token[i + 1]) + 1 == ord(token[i + 2])):
                sequential_count += 1

        return sequential_count > len(token) * 0.1

    async def _test_double_submit_weakness(
            self,
            url: str,
            method: str,
            endpoint: Dict[str, Any],
            protection_analysis: Dict[str, Any]
    ) -> Optional[AgentResult]:
        """Test double-submit cookie pattern for weaknesses."""
        try:
            test_token = "attacker_controlled_token_12345"

            response = await self.make_request(
                url,
                method=method,
                data={"csrf_token": test_token, "test": "value"},
                headers={"Cookie": f"csrf_token={test_token}"}
            )

            if response and response.status_code in CSRFConfig.SUCCESS_STATUS_CODES:
                return self.create_result(
                    vulnerability_type=VulnerabilityType.CSRF,
                    is_vulnerable=True,
                    severity=Severity.MEDIUM,
                    confidence=70,
                    url=url,
                    method=method,
                    title="Weak Double-Submit Cookie CSRF Protection",
                    description="Application accepts attacker-controlled token values",
                    evidence=f"Response status: {response.status_code}",
                    likelihood=5.0,
                    impact=7.0,
                    exploitability_rationale="Exploitable if attacker can set cookies",
                    remediation="Use signed double-submit cookies with HMAC",
                    owasp_category="A01:2021 – Broken Access Control",
                    cwe_id="CWE-352"
                )

        except Exception as e:
            logger.debug(f"Double-submit weakness test failed: {e}")

        return None

    async def _test_origin_referer_bypass(
            self,
            url: str,
            method: str,
            endpoint: Dict[str, Any]
    ) -> Optional[AgentResult]:
        """Test if origin/referer validation can be bypassed."""
        bypass_attempts = [
            ({"Origin": "null"}, "Null origin"),
            ({}, "Missing origin and referer headers"),
            ({"Referer": "data:text/html,<script>/* CSRF */</script>"}, "Data URI referer")
        ]

        test_data = endpoint.get("params", {}).copy() or {"test": "value"}

        for headers, description in bypass_attempts:
            try:
                response = await self.make_request(
                    url,
                    method=method,
                    data=test_data,
                    headers=headers
                )

                if response and response.status_code in CSRFConfig.SUCCESS_STATUS_CODES:
                    return self.create_result(
                        vulnerability_type=VulnerabilityType.CSRF,
                        is_vulnerable=True,
                        severity=Severity.MEDIUM,
                        confidence=80,
                        url=url,
                        method=method,
                        title="Origin/Referer Validation Bypass",
                        description=f"Endpoint accessible with {description.lower()}",
                        evidence=f"Bypass method: {description}",
                        likelihood=6.0,
                        impact=7.0,
                        exploitability_rationale=f"CSRF possible using {description.lower()}",
                        remediation="Strengthen origin validation",
                        owasp_category="A01:2021 – Broken Access Control",
                        cwe_id="CWE-352"
                    )

                await asyncio.sleep(CSRFConfig.REQUEST_DELAY)

            except Exception as e:
                logger.debug(f"Origin/referer bypass test failed: {e}")

        return None

    async def _check_global_protections(self, target_url: str) -> List[AgentResult]:
        """Check application-wide CSRF protection measures."""
        results: List[AgentResult] = []

        samesite_result = await self._check_samesite_cookies(target_url)
        if samesite_result:
            results.append(samesite_result)

        await asyncio.sleep(CSRFConfig.REQUEST_DELAY)

        cors_result = await self._check_cors_misconfiguration(target_url)
        if cors_result:
            results.append(cors_result)

        return results

    async def _check_samesite_cookies(self, url: str) -> Optional[AgentResult]:
        """Check if session cookies have proper SameSite attribute."""
        try:
            response = await self.make_request(url)
            if not response or not hasattr(response, 'headers'):
                return None

            set_cookies = []
            if hasattr(response.headers, 'get_list'):
                set_cookies = response.headers.get_list("set-cookie")
            else:
                set_cookie = response.headers.get("set-cookie", "")
                if set_cookie:
                    set_cookies = [set_cookie]

            for set_cookie in set_cookies:
                for pattern in CSRFConfig.SESSION_COOKIE_PATTERNS:
                    cookie_regex = rf'{pattern}[^;]*(?:;[^;]*)*'
                    match = re.search(cookie_regex, set_cookie, re.IGNORECASE)

                    if match:
                        cookie_str = match.group(0)

                        if "samesite" not in cookie_str.lower():
                            return self.create_result(
                                vulnerability_type=VulnerabilityType.CSRF,
                                is_vulnerable=True,
                                severity=Severity.LOW,
                                confidence=95,
                                url=url,
                                title="Session Cookie Missing SameSite Attribute",
                                description="Session cookies lack SameSite attribute",
                                evidence=f"Cookie: {cookie_str[:100]}...",
                                likelihood=3.0,
                                impact=5.0,
                                exploitability_rationale="Increases CSRF risk",
                                remediation="Set SameSite=Lax or Strict on session cookies",
                                owasp_category="A05:2021 – Security Misconfiguration",
                                cwe_id="CWE-1275"
                            )

                        if "samesite=none" in cookie_str.lower():
                            return self.create_result(
                                vulnerability_type=VulnerabilityType.CSRF,
                                is_vulnerable=True,
                                severity=Severity.MEDIUM,
                                confidence=90,
                                url=url,
                                title="Session Cookie Uses SameSite=None",
                                description="Session cookies use SameSite=None",
                                evidence=f"Cookie: {cookie_str[:100]}...",
                                likelihood=5.0,
                                impact=6.0,
                                exploitability_rationale="Disables SameSite protection",
                                remediation="Change to SameSite=Lax or Strict",
                                owasp_category="A05:2021 – Security Misconfiguration",
                                cwe_id="CWE-1275"
                            )

        except Exception as e:
            logger.error(f"SameSite cookie check error: {e}")

        return None

    async def _check_cors_misconfiguration(self, url: str) -> Optional[AgentResult]:
        """Check for CORS misconfigurations that enable CSRF."""
        try:
            response = await self.make_request(
                url,
                headers={"Origin": CSRFConfig.TEST_ORIGIN}
            )

            if not response or not hasattr(response, 'headers'):
                return None

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            if acao == CSRFConfig.TEST_ORIGIN and acac.lower() == "true":
                return self.create_result(
                    vulnerability_type=VulnerabilityType.CSRF,
                    is_vulnerable=True,
                    severity=Severity.HIGH,
                    confidence=90,
                    url=url,
                    title="CORS Misconfiguration Enables CSRF",
                    description="Application reflects arbitrary origins with credentials",
                    evidence=f"ACAO: {acao}\nACAC: {acac}",
                    likelihood=7.0,
                    impact=8.0,
                    exploitability_rationale="Enables cross-origin CSRF attacks",
                    remediation="Whitelist specific trusted origins only",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    cwe_id="CWE-942"
                )

            await asyncio.sleep(CSRFConfig.REQUEST_DELAY)

            null_response = await self.make_request(
                url,
                headers={"Origin": "null"}
            )

            if null_response and hasattr(null_response, 'headers'):
                null_acao = null_response.headers.get("Access-Control-Allow-Origin", "")
                if null_acao == "null":
                    return self.create_result(
                        vulnerability_type=VulnerabilityType.CSRF,
                        is_vulnerable=True,
                        severity=Severity.MEDIUM,
                        confidence=85,
                        url=url,
                        title="CORS Allows Null Origin",
                        description="Application accepts null origin",
                        evidence="ACAO: null",
                        likelihood=5.0,
                        impact=6.0,
                        remediation="Reject null origin requests",
                        owasp_category="A05:2021 – Security Misconfiguration",
                        cwe_id="CWE-942"
                    )

        except Exception as e:
            logger.error(f"CORS misconfiguration check error: {e}")

        return None

    async def _test_token_reuse(self, target_url: str) -> List[AgentResult]:
        """Test if CSRF tokens can be reused across requests."""
        results: List[AgentResult] = []

        if not self._discovered_tokens:
            return results

        test_url = list(self._discovered_tokens.keys())[0]
        token_info = self._discovered_tokens[test_url]

        try:
            success_count = 0

            for i in range(CSRFConfig.TOKEN_REUSE_TEST_COUNT):
                response = await self.make_request(
                    test_url,
                    method="POST",
                    data={
                        token_info.field_name: token_info.value,
                        "test_field": f"reuse_test_{i}"
                    }
                )

                if response and response.status_code in CSRFConfig.SUCCESS_STATUS_CODES:
                    success_count += 1

                await asyncio.sleep(CSRFConfig.REQUEST_DELAY)

            if success_count >= 2:
                token_sample = f"{token_info.value[:8]}..." if len(token_info.value) > 8 else "[redacted]"

                results.append(
                    self.create_result(
                        vulnerability_type=VulnerabilityType.CSRF,
                        is_vulnerable=True,
                        severity=Severity.MEDIUM,
                        confidence=85,
                        url=test_url,
                        title="CSRF Token Can Be Reused",
                        description="CSRF tokens are not invalidated after use",
                        evidence=f"Token reused {success_count} times\nToken: {token_sample}",
                        likelihood=4.0,
                        impact=5.0,
                        exploitability_rationale="Token reuse extends attack window",
                        remediation="Implement one-time tokens with invalidation after use",
                        owasp_category="A01:2021 – Broken Access Control",
                        cwe_id="CWE-352"
                    )
                )

        except Exception as e:
            logger.error(f"Token reuse test error: {e}")

        return results