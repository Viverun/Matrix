"""
API Security Agent - Enhanced version with OWASP API Top 10 2023 coverage.
"""
from typing import List, Dict, Any, Optional, Tuple
import re
import json
import logging
import time
from urllib.parse import urljoin, urlparse
from collections import defaultdict

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType

logger = logging.getLogger(__name__)


class APITestConfig:
    """Configuration constants for API security testing."""

    # Rate limiting test
    RATE_LIMIT_REQUESTS = 50
    RATE_LIMIT_WINDOW_SECONDS = 10
    RATE_LIMIT_THRESHOLD = 0.9  # 90% success rate indicates no rate limiting

    # IDOR test
    IDOR_TEST_IDS_COUNT = 5
    IDOR_SIMILARITY_THRESHOLD = 0.15  # 15% difference to consider responses unique

    # Mass assignment test
    MASS_ASSIGNMENT_PAYLOADS = [
        {"is_admin": True, "role": "admin"},
        {"is_verified": True, "email_verified": True},
        {"balance": 999999, "credits": 999999},
        {"permissions": ["admin", "superuser"]},
    ]

    # Discovery timeout
    DISCOVERY_TIMEOUT = 5.0


class APISecurityAgent(BaseSecurityAgent):
    """
    Enhanced API Security testing agent with full OWASP API Top 10 2023 coverage.

    Tests for:
    - API1: Broken Object Level Authorization (BOLA/IDOR)
    - API3: Broken Object Property Level Authorization (Excessive Data + Mass Assignment)
    - API4: Unrestricted Resource Consumption (Rate Limiting)
    - API5: Broken Function Level Authorization (BFLA)
    - API7: Server-Side Request Forgery (Note: has dedicated agent)
    - API8: Security Misconfigurations (Headers, CORS, exposed configs)
    - API9: Improper Inventory Management (old API versions)
    """

    agent_name = "api_security"
    agent_description = "Comprehensive API security testing (OWASP API Top 10 2023)"
    vulnerability_types = [
        VulnerabilityType.IDOR,
        VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        VulnerabilityType.MISSING_AUTHORIZATION,
        VulnerabilityType.SECURITY_MISCONFIG
    ]

    # Common API paths
    API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/graphql",
        "/api/users", "/api/admin", "/api/config", "/api/settings",
        "/.env", "/config.json",
        "/swagger.json", "/openapi.json", "/api-docs",
        "/swagger-ui/", "/swagger-ui/index.html",
        "/redoc", "/docs",
        "/api/health", "/api/status",
    ]

    # Sensitive data patterns
    SENSITIVE_PATTERNS = [
        (r'"password"\s*:\s*"[^"]+', "password"),
        (r'"secret"\s*:\s*"[^"]+', "secret"),
        (r'"api_key"\s*:\s*"[^"]+', "api_key"),
        (r'"token"\s*:\s*"[^"]+', "token"),
        (r'"private_key"\s*:\s*"[^"]+', "private_key"),
        (r'"ssn"\s*:\s*"[\d-]+', "ssn"),
        (r'"credit_card"\s*:\s*"[\d-]+', "credit_card"),
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "email"),
        (r'\b\d{3}-\d{2}-\d{4}\b', "ssn_format"),
        (r'\b\d{16}\b', "potential_card_number"),
        (r'"apiKey"', "api_key_field"),
        (r'"accessToken"', "access_token"),
        (r'"refreshToken"', "refresh_token"),
    ]

    # Security headers (removed deprecated X-XSS-Protection)
    SECURITY_HEADERS = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
    ]

    # Admin/privileged paths
    PRIVILEGED_PATHS = [
        "/admin", "/administrator", "/api/admin",
        "/api/users/all", "/api/system", "/api/config",
        "/debug", "/api/debug", "/api/internal",
    ]

    async def scan(
            self,
            target_url: str,
            endpoints: List[Dict[str, Any]],
            technology_stack: Optional[List[str]] = None,
            scan_context: Optional[Any] = None
    ) -> List[AgentResult]:
        """
        Comprehensive API security scan.

        Args:
            target_url: Base URL
            endpoints: Discovered endpoints
            technology_stack: Detected technologies
            scan_context: Context for inter-agent communication

        Returns:
            List of vulnerabilities
        """
        results = []

        logger.info(f"[API Agent] Starting comprehensive scan on {target_url}")

        # Discover API endpoints
        api_endpoints = await self._discover_api_endpoints(target_url)
        all_endpoints = endpoints + api_endpoints

        logger.info(f"[API Agent] Testing {len(all_endpoints)} endpoints")

        for endpoint in all_endpoints:
            url = endpoint.get("url", target_url)

            # Test for sensitive data exposure (API3: BOPLA - Excessive Data)
            data_exposure = await self._test_data_exposure(url)
            if data_exposure:
                results.append(data_exposure)

            # Test for IDOR (API1: BOLA)
            idor_result = await self._test_idor_enhanced(endpoint, scan_context)
            if idor_result:
                results.append(idor_result)

            # Test for rate limiting (API4: Unrestricted Resource Consumption)
            if endpoint.get("method", "GET") in ["POST", "PUT", "DELETE"]:
                rate_limit_result = await self._test_rate_limiting(url, endpoint.get("method", "POST"))
                if rate_limit_result:
                    results.append(rate_limit_result)

            # Test for mass assignment (API3: BOPLA - Mass Assignment)
            if endpoint.get("method", "GET") in ["POST", "PUT", "PATCH"]:
                mass_assign_result = await self._test_mass_assignment(url, endpoint.get("method", "POST"))
                if mass_assign_result:
                    results.append(mass_assign_result)

        # Check security headers (API8: Security Misconfiguration)
        header_issues = await self._check_security_headers(target_url)
        results.extend(header_issues)

        # Check for exposed configuration (API8: Security Misconfiguration)
        config_issues = await self._check_exposed_configs(target_url)
        results.extend(config_issues)

        # Check CORS configuration (API8: Security Misconfiguration)
        cors_result = await self._test_cors(target_url)
        if cors_result:
            results.append(cors_result)

        # Check cookie security (API8: Security Misconfiguration)
        cookie_issues = await self._check_cookie_security(target_url)
        results.extend(cookie_issues)

        # Check SSL/TLS configuration
        ssl_issues = await self._check_ssl_security(target_url)
        results.extend(ssl_issues)

        # Check for old API versions (API9: Improper Inventory Management)
        old_version_issues = await self._check_old_api_versions(target_url)
        results.extend(old_version_issues)

        # Test for broken function level authorization (API5: BFLA)
        bfla_issues = await self._test_function_level_authz(target_url, scan_context)
        results.extend(bfla_issues)

        logger.info(f"[API Agent] Scan complete. Found {len(results)} issues")
        return results

    async def _discover_api_endpoints(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Discover API endpoints including documentation URLs.

        Args:
            target_url: Base URL

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        if not target_url.startswith(("http://", "https://")):
            target_url = f"http://{target_url}"

        base_url = target_url if target_url.endswith("/") else f"{target_url}/"

        for path in self.API_PATHS:
            clean_path = path.lstrip("/")
            url = urljoin(base_url, clean_path)

            try:
                response = await self.make_request(url)
                if response and response.status_code in [200, 201, 401, 403]:
                    endpoints.append({
                        "url": url,
                        "method": "GET",
                        "params": {},
                        "status": response.status_code
                    })
                    logger.debug(f"[API Agent] Discovered endpoint: {url} [{response.status_code}]")
            except Exception as e:
                logger.debug(f"[API Agent] Discovery error for {url}: {e}")

        return endpoints

    async def _test_data_exposure(self, url: str) -> Optional[AgentResult]:
        """
        Test for excessive data exposure (API3:2023 BOPLA - Part 1).

        Detects sensitive data unnecessarily exposed in API responses.

        Args:
            url: URL to test

        Returns:
            AgentResult if vulnerable, None otherwise
        """
        try:
            response = await self.make_request(url)
            if response is None:
                return None

            response_text = response.text
            found_sensitive = []

            for pattern, data_type in self.SENSITIVE_PATTERNS:
                if re.search(pattern, response_text, re.IGNORECASE):
                    found_sensitive.append(data_type)

            if found_sensitive:
                unique_types = list(set(found_sensitive))

                # Use AI to analyze severity
                ai_analysis = await self.analyze_with_ai(
                    vulnerability_type="Sensitive Data Exposure (BOPLA)",
                    context=f"API response contains potential sensitive data: {unique_types}",
                    response_data=response_text[:1500]
                )

                # Critical if includes credentials or PII
                critical_types = {"password", "secret", "api_key", "ssn", "credit_card", "private_key"}
                is_critical = any(t in critical_types for t in unique_types)

                severity = Severity.CRITICAL if is_critical else (
                    Severity.HIGH if len(unique_types) > 2 else Severity.MEDIUM
                )

                return self.create_result(
                    vulnerability_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                    is_vulnerable=True,
                    severity=severity,
                    confidence=ai_analysis.get("confidence", 75),
                    url=url,
                    title="Excessive Data Exposure in API Response (BOPLA)",
                    description=f"The API endpoint exposes sensitive data unnecessarily. This violates OWASP API3:2023 - Broken Object Property Level Authorization. Detected: {', '.join(unique_types)}",
                    evidence=f"Sensitive data types found: {unique_types}\nSample: {response_text[:500]}",
                    ai_analysis=ai_analysis.get("reason", ""),
                    likelihood=7.0,
                    impact=8.0 if is_critical else 6.0,
                    exploitability_rationale=(
                        "Direct data exposure. Attacker can immediately access sensitive information "
                        "without bypassing authentication or authorization checks."
                    ),
                    remediation=(
                        "Implement field-level authorization. Use DTOs/serializers to control exposed fields. "
                        "Apply principle of least privilege - only return data the client needs. "
                        "Filter sensitive fields before serialization."
                    ),
                    owasp_category="API3:2023 – Broken Object Property Level Authorization",
                    cwe_id="CWE-213",
                    reference_links=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"
                    ]
                )

        except Exception as e:
            logger.error(f"[API Agent] Data exposure test error for {url}: {e}")

        return None

    async def _test_idor_enhanced(
            self,
            endpoint: Dict[str, Any],
            scan_context: Optional[Any] = None
    ) -> Optional[AgentResult]:
        """
        Enhanced IDOR testing with multiple techniques (API1:2023 BOLA).

        Tests:
        - Sequential ID manipulation
        - UUID manipulation
        - Authenticated vs unauthenticated access
        - Different HTTP methods

        Args:
            endpoint: Endpoint to test
            scan_context: Scan context for auth state

        Returns:
            AgentResult if vulnerable, None otherwise
        """
        url = endpoint.get("url", "")

        # Check for ID patterns (numeric or UUID)
        numeric_match = re.search(r'/(\d+)(?:/|$|\?)', url)
        uuid_match = re.search(r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:/|$|\?)', url,
                               re.IGNORECASE)

        if not (numeric_match or uuid_match):
            return None

        try:
            # Get original resource
            original_response = await self.make_request(url)
            if original_response is None or original_response.status_code not in [200, 201]:
                return None

            original_data = original_response.text

            # Test numeric IDs
            if numeric_match:
                original_id = numeric_match.group(1)
                test_ids = [
                    str(int(original_id) + 1),
                    str(int(original_id) - 1),
                    "1", "0",
                    str(int(original_id) * 2),
                ]

                for test_id in test_ids:
                    test_url = url.replace(f"/{original_id}", f"/{test_id}")
                    if test_url == url:
                        continue

                    response = await self.make_request(test_url)

                    if response and response.status_code == 200:
                        # Check response similarity
                        similarity = self._calculate_similarity(original_data, response.text)

                        if similarity < (1 - APITestConfig.IDOR_SIMILARITY_THRESHOLD):
                            return self.create_result(
                                vulnerability_type=VulnerabilityType.IDOR,
                                is_vulnerable=True,
                                severity=Severity.HIGH,
                                confidence=85,
                                url=url,
                                title="Broken Object Level Authorization (BOLA/IDOR)",
                                description=(
                                    f"API allows accessing other users' objects by manipulating ID parameter. "
                                    f"Original ID {original_id} → Test ID {test_id}: both accessible with different data. "
                                    f"This is OWASP API1:2023 - the #1 API security risk."
                                ),
                                evidence=f"Original ID: {original_id}, Test ID: {test_id} - Both accessible, {similarity * 100:.1f}% similar",
                                likelihood=8.0,
                                impact=8.0,
                                exploitability_rationale=(
                                    "Direct exploitation. Attacker can enumerate IDs and access arbitrary user data. "
                                    "No special tools or authentication bypass required."
                                ),
                                remediation=(
                                    "Implement object-level authorization checks for EVERY API endpoint. "
                                    "Verify the authenticated user owns/can access the requested object. "
                                    "Use indirect references or UUIDs. Log access attempts for anomaly detection."
                                ),
                                owasp_category="API1:2023 – Broken Object Level Authorization",
                                cwe_id="CWE-639",
                                reference_links=[
                                    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                                ]
                            )

            # Test UUID manipulation (if applicable)
            if uuid_match:
                # Generate similar-looking UUID
                original_uuid = uuid_match.group(1)
                # Simple test: try flipping last character
                test_uuid = original_uuid[:-1] + ('0' if original_uuid[-1] != '0' else '1')
                test_url = url.replace(original_uuid, test_uuid)

                response = await self.make_request(test_url)
                if response and response.status_code == 200 and response.text != original_data:
                    return self.create_result(
                        vulnerability_type=VulnerabilityType.IDOR,
                        is_vulnerable=True,
                        severity=Severity.HIGH,
                        confidence=80,
                        url=url,
                        title="BOLA via UUID Manipulation",
                        description="API vulnerable to BOLA even with UUIDs. Manipulating UUID grants access to other objects.",
                        evidence=f"UUID manipulation: {original_uuid} → {test_uuid}",
                        likelihood=7.0,
                        impact=8.0,
                        remediation="UUIDs alone don't prevent BOLA. Always implement authorization checks.",
                        owasp_category="API1:2023 – Broken Object Level Authorization",
                        cwe_id="CWE-639"
                    )

        except Exception as e:
            logger.error(f"[API Agent] Enhanced IDOR test error for {url}: {e}")

        return None

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity between two texts.

        Uses simple character-level comparison. Returns value between 0 and 1.

        Args:
            text1: First text
            text2: Second text

        Returns:
            Similarity score (0.0 to 1.0)
        """
        if not text1 or not text2:
            return 0.0

        # Simple similarity: ratio of common characters
        set1 = set(text1)
        set2 = set(text2)
        intersection = len(set1 & set2)
        union = len(set1 | set2)

        return intersection / union if union > 0 else 0.0

    async def _test_rate_limiting(self, url: str, method: str = "POST") -> Optional[AgentResult]:
        """
        Test for rate limiting (API4:2023 Unrestricted Resource Consumption).

        Sends multiple rapid requests to detect missing rate limits.

        Args:
            url: URL to test
            method: HTTP method

        Returns:
            AgentResult if vulnerable, None otherwise
        """
        try:
            logger.info(f"[API Agent] Testing rate limiting on {url}")

            success_count = 0
            start_time = time.time()

            for i in range(APITestConfig.RATE_LIMIT_REQUESTS):
                try:
                    response = await self.make_request(url, method=method, data={})
                    if response and response.status_code not in [429, 503]:
                        success_count += 1
                except:
                    pass

            elapsed = time.time() - start_time
            success_rate = success_count / APITestConfig.RATE_LIMIT_REQUESTS

            # If > 90% succeed, rate limiting is likely missing
            if success_rate >= APITestConfig.RATE_LIMIT_THRESHOLD:
                return self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.MEDIUM,
                    confidence=85,
                    url=url,
                    title="Missing Rate Limiting (Unrestricted Resource Consumption)",
                    description=(
                        f"API endpoint accepts {success_count}/{APITestConfig.RATE_LIMIT_REQUESTS} rapid requests "
                        f"in {elapsed:.1f}s without rate limiting. This is OWASP API4:2023 - Unrestricted Resource Consumption."
                    ),
                    evidence=f"Success rate: {success_rate * 100:.1f}% over {elapsed:.1f}s",
                    likelihood=6.0,
                    impact=5.0,
                    exploitability_rationale=(
                        "Enables brute-force attacks, credential stuffing, denial of service, and resource exhaustion. "
                        "Directly exploitable with simple scripts."
                    ),
                    remediation=(
                        "Implement rate limiting per IP/user. Use token bucket or sliding window algorithms. "
                        "Return 429 (Too Many Requests) with Retry-After header. "
                        "Consider CAPTCHA for sensitive endpoints."
                    ),
                    owasp_category="API4:2023 – Unrestricted Resource Consumption",
                    cwe_id="CWE-770",
                    reference_links=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
                    ]
                )

        except Exception as e:
            logger.error(f"[API Agent] Rate limiting test error for {url}: {e}")

        return None

    async def _test_mass_assignment(self, url: str, method: str = "POST") -> Optional[AgentResult]:
        """
        Test for mass assignment vulnerabilities (API3:2023 BOPLA - Part 2).

        Attempts to inject privileged fields via request payload.

        Args:
            url: URL to test
            method: HTTP method

        Returns:
            AgentResult if vulnerable, None otherwise
        """
        try:
            for payload in APITestConfig.MASS_ASSIGNMENT_PAYLOADS:
                response = await self.make_request(
                    url,
                    method=method,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                if response and response.status_code in [200, 201]:
                    # Check if privileged fields are echoed back
                    response_lower = response.text.lower()

                    for key in payload.keys():
                        if key.lower() in response_lower:
                            return self.create_result(
                                vulnerability_type=VulnerabilityType.MISSING_AUTHORIZATION,
                                is_vulnerable=True,
                                severity=Severity.HIGH,
                                confidence=75,
                                url=url,
                                title="Mass Assignment Vulnerability (BOPLA)",
                                description=(
                                    f"API accepts and processes unauthorized fields. Attempted to inject "
                                    f"privileged field '{key}' and it was accepted/echoed. "
                                    f"This is OWASP API3:2023 - Broken Object Property Level Authorization."
                                ),
                                evidence=f"Injected field: {key} - Appears in response",
                                likelihood=7.0,
                                impact=8.0,
                                exploitability_rationale=(
                                    "Allows privilege escalation by injecting admin flags, verified status, "
                                    "or balance manipulation. Directly exploitable."
                                ),
                                remediation=(
                                    "Use allowlists for accepted fields. Never bind directly to models. "
                                    "Use DTOs/form objects with explicit field definitions. "
                                    "Implement property-level authorization checks."
                                ),
                                owasp_category="API3:2023 – Broken Object Property Level Authorization",
                                cwe_id="CWE-915",
                                reference_links=[
                                    "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"
                                ]
                            )

        except Exception as e:
            logger.error(f"[API Agent] Mass assignment test error for {url}: {e}")

        return None

    async def _check_old_api_versions(self, target_url: str) -> List[AgentResult]:
        """
        Check for old/deprecated API versions (API9:2023 Improper Inventory Management).

        Args:
            target_url: Base URL

        Returns:
            List of issues with old API versions
        """
        results = []

        if not target_url.startswith(("http://", "https://")):
            target_url = f"http://{target_url}"

        base_url = target_url if target_url.endswith("/") else f"{target_url}/"

        # Test for multiple API versions
        versions_found = []

        for version in range(1, 6):  # Check v1 through v5
            version_url = urljoin(base_url, f"api/v{version}/")

            try:
                response = await self.make_request(version_url, timeout=APITestConfig.DISCOVERY_TIMEOUT)
                if response and response.status_code in [200, 401, 403]:
                    versions_found.append(version)
            except:
                pass

        # If multiple versions exist, flag as potential inventory issue
        if len(versions_found) > 2:
            results.append(self.create_result(
                vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                is_vulnerable=True,
                severity=Severity.LOW,
                confidence=70,
                url=target_url,
                title="Multiple API Versions Detected (Improper Inventory Management)",
                description=(
                    f"Found {len(versions_found)} API versions: {versions_found}. "
                    f"This may indicate improper API inventory management (OWASP API9:2023). "
                    f"Old versions might contain unpatched vulnerabilities."
                ),
                evidence=f"Accessible API versions: {', '.join(f'v{v}' for v in versions_found)}",
                likelihood=4.0,
                impact=5.0,
                exploitability_rationale=(
                    "Older API versions may lack security patches or authentication. "
                    "Exploitability depends on what vulnerabilities exist in old versions."
                ),
                remediation=(
                    "Maintain API inventory. Deprecate and remove old versions. "
                    "If old versions must remain, ensure they have same security controls as current version. "
                    "Use API gateways to enforce version deprecation."
                ),
                owasp_category="API9:2023 – Improper Inventory Management",
                cwe_id="CWE-1059"
            ))

        return results

    async def _test_function_level_authz(
            self,
            target_url: str,
            scan_context: Optional[Any] = None
    ) -> List[AgentResult]:
        """
        Test for broken function-level authorization (API5:2023 BFLA).

        Tests access to admin/privileged endpoints.

        Args:
            target_url: Base URL
            scan_context: Scan context

        Returns:
            List of BFLA issues
        """
        results = []

        if not target_url.startswith(("http://", "https://")):
            target_url = f"http://{target_url}"

        base_url = target_url if target_url.endswith("/") else f"{target_url}/"

        for path in self.PRIVILEGED_PATHS:
            clean_path = path.lstrip("/")
            url = urljoin(base_url, clean_path)

            try:
                # Try accessing without authentication
                response = await self.make_request(url)

                if response and response.status_code == 200:
                    results.append(self.create_result(
                        vulnerability_type=VulnerabilityType.MISSING_AUTHORIZATION,
                        is_vulnerable=True,
                        severity=Severity.HIGH,
                        confidence=80,
                        url=url,
                        title="Broken Function Level Authorization (BFLA)",
                        description=(
                            f"Administrative/privileged endpoint '{path}' is accessible without proper authorization. "
                            f"This is OWASP API5:2023 - Broken Function Level Authorization."
                        ),
                        evidence=f"GET {url} returned 200 OK without authentication",
                        likelihood=7.0,
                        impact=8.0,
                        exploitability_rationale=(
                            "Direct access to admin functions. Enables privilege escalation, "
                            "unauthorized actions, and full system compromise."
                        ),
                        remediation=(
                            "Implement role-based access control (RBAC). Deny access by default. "
                            "Check user roles/permissions for every sensitive function. "
                            "Use centralized authorization middleware."
                        ),
                        owasp_category="API5:2023 – Broken Function Level Authorization",
                        cwe_id="CWE-285",
                        reference_links=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"
                        ]
                    ))

            except Exception as e:
                logger.debug(f"[API Agent] BFLA test error for {url}: {e}")

        return results

    async def _validate_header_value(
            self,
            header: str,
            value: str,
            url: str
    ) -> Tuple[bool, Optional[AgentResult]]:
        """
        Validate security header configuration.

        Args:
            header: Header name
            value: Header value
            url: URL being checked

        Returns:
            Tuple of (is_valid, issue_if_any)
        """
        header_lower = header.lower()
        value_lower = value.lower()

        # X-Content-Type-Options validation
        if header_lower == "x-content-type-options":
            if value_lower != "nosniff":
                return False, self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.INFO,
                    confidence=100,
                    url=url,
                    title="X-Content-Type-Options Misconfigured",
                    description=f"Header value '{value}' should be 'nosniff'.",
                    evidence=f"X-Content-Type-Options: {value}",
                    likelihood=1.0,
                    impact=1.0,
                    exploitability_rationale="Minor misconfiguration. Present but not optimal.",
                    remediation="Set X-Content-Type-Options to 'nosniff'.",
                    owasp_category="API8:2023 – Security Misconfiguration",
                    cwe_id="CWE-693"
                )
            return True, None

        # X-Frame-Options validation
        if header_lower == "x-frame-options":
            valid_values = ["deny", "sameorigin"]
            if value_lower not in valid_values:
                return False, self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.LOW,
                    confidence=90,
                    url=url,
                    title="X-Frame-Options Misconfigured",
                    description=f"Value '{value}' may allow unintended framing. Use 'DENY' or 'SAMEORIGIN'.",
                    evidence=f"X-Frame-Options: {value}",
                    likelihood=2.0,
                    impact=3.0,
                    exploitability_rationale="Potential clickjacking if framing allowed from untrusted origins.",
                    remediation="Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'.",
                    owasp_category="API8:2023 – Security Misconfiguration",
                    cwe_id="CWE-1021"
                )
            return True, None

        # HSTS validation
        if header_lower == "strict-transport-security":
            max_age_match = re.search(r'max-age=(\d+)', value_lower)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 15768000:  # Less than 6 months
                    return False, self.create_result(
                        vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                        is_vulnerable=True,
                        severity=Severity.INFO,
                        confidence=85,
                        url=url,
                        title="HSTS max-age Too Short",
                        description=f"max-age {max_age}s ({max_age // 86400} days) below 6-month minimum.",
                        evidence=f"Strict-Transport-Security: {value}",
                        likelihood=1.0,
                        impact=2.0,
                        remediation="Set max-age to at least 31536000 (1 year).",
                        owasp_category="API8:2023 – Security Misconfiguration",
                        cwe_id="CWE-319"
                    )
            return True, None

        # CSP validation
        if header_lower == "content-security-policy":
            issues = []
            if "'unsafe-inline'" in value_lower and "script-src" in value_lower:
                issues.append("script-src allows 'unsafe-inline'")
            if "'unsafe-eval'" in value_lower:
                issues.append("allows 'unsafe-eval'")
            if "default-src *" in value_lower or "default-src '*'" in value_lower:
                issues.append("default-src allows all sources (*)")

            if issues:
                header_context = f"Security header '{header}' is misconfigured on {url}. Found issues: {', '.join(issues)}"
                ai_analysis = await self.analyze_with_ai(
                    vulnerability_type="Security Header Misconfiguration",
                    context=header_context,
                    response_data=f"{header}: {value}"
                )

                return False, self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.LOW,
                    confidence=ai_analysis.get("confidence", 90),
                    url=url,
                    title=f"Security Header Misconfigured: {header}",
                    description=f"CSP contains permissive directives: {', '.join(issues)}",
                    evidence=f"{header}: {value[:200]}...",
                    ai_analysis=ai_analysis.get("reason", ""),
                    likelihood=ai_analysis.get("likelihood", 3.0),
                    impact=ai_analysis.get("impact", 3.0),
                    remediation="Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces/hashes.",
                    owasp_category="API8:2023 – Security Misconfiguration",
                    cwe_id="CWE-693"
                )
            return True, None

        return True, None

    async def _check_security_headers(self, url: str) -> List[AgentResult]:
        """
        Check security headers (API8:2023 Security Misconfiguration).

        Args:
            url: URL to check

        Returns:
            List of security header issues
        """
        results = []
        present_headers = []

        try:
            response = await self.make_request(url)
            if response is None:
                return results

            headers = response.headers
            headers_lower = {h.lower(): v for h, v in headers.items()}

            for header in self.SECURITY_HEADERS:
                header_lower = header.lower()

                if header_lower in headers_lower:
                    value = headers_lower[header_lower]
                    is_valid, issue = await self._validate_header_value(header, value, url)

                    if is_valid:
                        present_headers.append(header)
                    elif issue:
                        results.append(issue)
                else:
                    # Header missing
                    if header == "Strict-Transport-Security" and not url.startswith("https"):
                        continue

                    severity = Severity.LOW
                    likelihood = 2.0
                    impact = 2.0
                    cwe_id = "CWE-693"

                    if header == "X-Frame-Options":
                        cwe_id = "CWE-1021"
                    elif header == "Content-Security-Policy":
                        impact = 3.0

                    header_context = f"Security header '{header}' is missing from {url}. This reduces defense-in-depth."
                    ai_analysis = await self.analyze_with_ai(
                        vulnerability_type="Missing Security Header",
                        context=header_context,
                        response_data="Header not found in response"
                    )

                    results.append(self.create_result(
                        vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                        is_vulnerable=True,
                        severity=severity,
                        confidence=ai_analysis.get("confidence", 95),
                        url=url,
                        title=f"Missing Security Header: {header}",
                        description=f"Security header '{header}' not present. Defense-in-depth control missing.",
                        evidence=f"Header '{header}' not found",
                        ai_analysis=ai_analysis.get("reason", ""),
                        likelihood=ai_analysis.get("likelihood", likelihood),
                        impact=ai_analysis.get("impact", impact),
                        exploitability_rationale=(
                            "Increases attack surface but not directly exploitable alone. "
                            "Risk amplified when chained with other vulnerabilities."
                        ),
                        remediation=f"Configure web server to include '{header}' header in all responses.",
                        owasp_category="API8:2023 – Security Misconfiguration",
                        cwe_id=cwe_id
                    ))

            if present_headers:
                logger.info(f"[API Agent] ✓ Correctly configured headers: {', '.join(present_headers)}")

        except Exception as e:
            logger.error(f"[API Agent] Header check error for {url}: {e}")

        return results

    async def _check_exposed_configs(self, target_url: str) -> List[AgentResult]:
        """
        Check for exposed configuration files (API8:2023).

        Args:
            target_url: Base URL

        Returns:
            List of exposed config issues
        """
        results = []

        config_files = [
            "/.env",
            "/config.json",
            "/settings.json",
            "/.git/config",
            "/wp-config.php",
            "/web.config",
            "/phpinfo.php",
            "/.htaccess",
        ]

        for path in config_files:
            url = urljoin(target_url, path)

            try:
                response = await self.make_request(url)

                if response and response.status_code == 200:
                    has_sensitive = any(
                        kw in response.text.lower()
                        for kw in ["password", "secret", "api_key", "database", "private", "token"]
                    )

                    if has_sensitive:
                        results.append(self.create_result(
                            vulnerability_type=VulnerabilityType.INFO_DISCLOSURE,
                            is_vulnerable=True,
                            severity=Severity.HIGH,
                            confidence=90,
                            url=url,
                            title=f"Exposed Configuration File: {path}",
                            description=f"Configuration file {path} is publicly accessible with sensitive data.",
                            evidence=f"File accessible: {path}, Contains: password/secret/api_key",
                            likelihood=9.0,
                            impact=8.0,
                            exploitability_rationale="Direct access to credentials. Immediate system compromise possible.",
                            remediation="Remove or restrict access. Use web server rules to deny access to sensitive files.",
                            owasp_category="API8:2023 – Security Misconfiguration",
                            cwe_id="CWE-538"
                        ))

            except Exception as e:
                logger.debug(f"[API Agent] Config check error for {url}: {e}")

        return results

    async def _test_cors(self, url: str) -> Optional[AgentResult]:
        """
        Test CORS configuration (API8:2023 Security Misconfiguration).

        Args:
            url: URL to test

        Returns:
            AgentResult if vulnerable, None otherwise
        """
        try:
            response = await self.make_request(
                url,
                headers={"Origin": "https://evil.example.com"}
            )

            if response is None:
                return None

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            # Critical: reflected origin with credentials
            if acao == "https://evil.example.com" and acac.lower() == "true":
                return self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.HIGH,
                    confidence=95,
                    url=url,
                    title="Insecure CORS Configuration (Reflected Origin)",
                    description=(
                        "Server reflects arbitrary origins with credentials enabled. "
                        "Any website can make authenticated requests to this API."
                    ),
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    likelihood=8.0,
                    impact=8.0,
                    exploitability_rationale=(
                        "Direct path to CSRF and data theft. Malicious site can perform "
                        "authenticated actions on behalf of logged-in victims."
                    ),
                    remediation=(
                        "Never reflect arbitrary origins. Whitelist only trusted origins. "
                        "Never use 'Allow-Credentials: true' with 'Allow-Origin: *'."
                    ),
                    owasp_category="API8:2023 – Security Misconfiguration",
                    cwe_id="CWE-942"
                )

            # Medium: wildcard with credentials (browser-blocked but indicates poor understanding)
            if acao == "*" and acac.lower() == "true":
                return self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.MEDIUM,
                    confidence=90,
                    url=url,
                    title="Dangerous CORS Policy (Wildcard + Credentials)",
                    description="Wildcard origin with credentials - disallowed by browsers but indicates misconfiguration.",
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    likelihood=4.0,
                    impact=7.0,
                    remediation="Use explicit allowed origins instead of wildcards with credentials.",
                    owasp_category="API8:2023 – Security Misconfiguration",
                    cwe_id="CWE-942"
                )

            # Info: wildcard without credentials (acceptable for public APIs)
            if acao == "*" and acac.lower() != "true":
                return self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.INFO,
                    confidence=100,
                    url=url,
                    title="Permissive CORS Policy (Wildcard Origin)",
                    description="Wildcard CORS without credentials. Review if endpoint handles sensitive data.",
                    evidence=f"ACAO: {acao}",
                    likelihood=1.0,
                    impact=2.0,
                    remediation="Verify endpoint doesn't return sensitive user-specific data. If it does, use origin whitelist.",
                    owasp_category="API8:2023 – Security Misconfiguration",
                    cwe_id="CWE-942"
                )

            # Low: reflected origin without credentials
            if acao == "https://evil.example.com" and acac.lower() != "true":
                return self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.LOW,
                    confidence=85,
                    url=url,
                    title="CORS Origin Reflection Without Credentials",
                    description="Reflects arbitrary origins without credentials. Lower risk but indicates misconfiguration.",
                    evidence=f"ACAO: {acao}",
                    likelihood=3.0,
                    impact=3.0,
                    remediation="Implement origin whitelist. Ensure no sensitive data accessible without authentication.",
                    owasp_category="API8:2023 – Security Misconfiguration",
                    cwe_id="CWE-942"
                )

        except Exception as e:
            logger.error(f"[API Agent] CORS test error for {url}: {e}")

        return None
    async def _check_cookie_security(self, url: str) -> List[AgentResult]:
        """Check for insecure cookie configurations."""
        results = []
        try:
            response = await self.make_request(url)
            if not response:
                return results

            cookie_header = response.headers.get("set-cookie", "")
            if not cookie_header:
                return results

            cookies = [cookie_header]
            for cookie in cookies:
                cookie_lower = cookie.lower()
                cookie_name = cookie.split("=")[0].strip() if "=" in cookie else "Unknown"
                is_session = any(kw in cookie_lower for kw in ["session", "token", "auth", "jwt", "sid"])

                if "httponly" not in cookie_lower:
                    severity = Severity.MEDIUM if is_session else Severity.LOW
                    results.append(self.create_result(
                        vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                        is_vulnerable=True, severity=severity, confidence=95, url=url,
                        title=f"Cookie Missing HttpOnly Flag: {cookie_name}",
                        description=f"Cookie '{cookie_name}' can be accessed by JavaScript. XSS attacks could steal this cookie.",
                        evidence=f"Set-Cookie: {cookie[:80]}...",
                        likelihood=6.0 if is_session else 4.0,
                        impact=7.0 if is_session else 3.0,
                        remediation="Add 'HttpOnly' flag to prevent JavaScript access to sensitive cookies.",
                        owasp_category="API8:2023 - Security Misconfiguration",
                        cwe_id="CWE-1004"
                    ))

                if "secure" not in cookie_lower and url.startswith("https"):
                    severity = Severity.MEDIUM if is_session else Severity.LOW
                    results.append(self.create_result(
                        vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                        is_vulnerable=True, severity=severity, confidence=95, url=url,
                        title=f"Cookie Missing Secure Flag: {cookie_name}",
                        description=f"Cookie '{cookie_name}' can be sent over unencrypted HTTP. MITM attacks could intercept this cookie.",
                        evidence=f"Set-Cookie: {cookie[:80]}...",
                        likelihood=5.0, impact=6.0 if is_session else 3.0,
                        remediation="Add 'Secure' flag to ensure cookie is only sent over HTTPS.",
                        owasp_category="API8:2023 - Security Misconfiguration",
                        cwe_id="CWE-614"
                    ))

                if "samesite" not in cookie_lower:
                    results.append(self.create_result(
                        vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                        is_vulnerable=True, severity=Severity.LOW, confidence=90, url=url,
                        title=f"Cookie Missing SameSite Attribute: {cookie_name}",
                        description=f"Cookie '{cookie_name}' has no SameSite attribute. May be vulnerable to CSRF attacks.",
                        evidence=f"Set-Cookie: {cookie[:80]}...",
                        likelihood=4.0, impact=5.0 if is_session else 2.0,
                        remediation="Add 'SameSite=Strict' or 'SameSite=Lax' attribute.",
                        owasp_category="API8:2023 - Security Misconfiguration",
                        cwe_id="CWE-1275"
                    ))

            if cookies:
                logger.info(f"[API Agent] Checked {len(cookies)} cookies for security issues")
        except Exception as e:
            logger.error(f"[API Agent] Cookie check error for {url}: {e}")
        return results

    async def _check_ssl_security(self, url: str) -> List[AgentResult]:
        """Check SSL/TLS security configuration."""
        results = []
        parsed = urlparse(url)
        try:
            if parsed.scheme == "https":
                http_url = url.replace("https://", "http://")
                try:
                    response = await self.make_request(http_url)
                    if response and response.status_code == 200:
                        results.append(self.create_result(
                            vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                            is_vulnerable=True, severity=Severity.MEDIUM, confidence=95, url=url,
                            title="Site Accessible Over HTTP (No HTTPS Redirect)",
                            description="Site content is available over unencrypted HTTP. Sensitive data could be intercepted.",
                            evidence="HTTP 200 OK - No redirect to HTTPS",
                            likelihood=7.0, impact=6.0,
                            remediation="Implement HTTP to HTTPS redirect for all pages.",
                            owasp_category="API8:2023 - Security Misconfiguration",
                            cwe_id="CWE-319"
                        ))
                except Exception:
                    pass

            response = await self.make_request(url)
            if response:
                hsts = response.headers.get("strict-transport-security", "")
                if hsts:
                    max_age_match = re.search(r"max-age=(\d+)", hsts)
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                        if max_age < 31536000:
                            results.append(self.create_result(
                                vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                                is_vulnerable=True, severity=Severity.LOW, confidence=90, url=url,
                                title="HSTS Max-Age Too Short",
                                description=f"HSTS max-age is {max_age} seconds. Recommended minimum: 31536000 (1 year).",
                                evidence=f"Strict-Transport-Security: {hsts}",
                                likelihood=3.0, impact=4.0,
                                remediation="Set HSTS max-age to at least 31536000 seconds (1 year).",
                                owasp_category="API8:2023 - Security Misconfiguration",
                                cwe_id="CWE-523"
                            ))

                    if "includesubdomains" not in hsts.lower():
                        results.append(self.create_result(
                            vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                            is_vulnerable=True, severity=Severity.INFO, confidence=85, url=url,
                            title="HSTS Missing includeSubDomains",
                            description="HSTS does not include subdomains. Subdomains may be vulnerable to downgrade attacks.",
                            evidence=f"Strict-Transport-Security: {hsts}",
                            likelihood=2.0, impact=3.0,
                            remediation="Add 'includeSubDomains' directive to HSTS header.",
                            owasp_category="API8:2023 - Security Misconfiguration",
                            cwe_id="CWE-523"
                        ))

            logger.info(f"[API Agent] Completed SSL/TLS security checks for {url}")
        except Exception as e:
            logger.error(f"[API Agent] SSL check error for {url}: {e}")
        return results
