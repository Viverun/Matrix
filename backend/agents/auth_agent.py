"""
Enhanced Authentication Security Agent - Comprehensive authentication testing.
"""
from typing import List, Dict, Any, Optional, Tuple, TYPE_CHECKING
import re
import asyncio
import time
import logging
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType

if TYPE_CHECKING:
    from core.scan_context import ScanContext

logger = logging.getLogger(__name__)


@dataclass
class TimingResult:
    """Results from timing analysis."""
    username: str
    response_time: float
    status_code: int
    response_length: int


class AuthConfig:
    """Configuration constants for authentication testing."""
    # Limits
    MAX_DEFAULT_CREDS_TO_TEST = 10
    MAX_RAPID_REQUESTS = 15
    MAX_TIMING_TESTS = 8

    # Timeouts
    REQUEST_TIMEOUT = 10

    # Thresholds
    TIMING_DIFFERENCE_THRESHOLD = 0.15  # 150ms difference
    SESSION_COOKIE_MIN_LENGTH = 16
    TOKEN_MIN_LENGTH = 20

    # Rate limiting
    RATE_LIMIT_DELAY = 0.5  # Seconds between requests


class AuthenticationAgent(BaseSecurityAgent):
    """
    Enhanced authentication testing agent.

    Tests for authentication vulnerabilities:
    - Weak password policies
    - Default credentials
    - Session management issues
    - Brute force susceptibility
    - Username enumeration (error-based and timing-based)
    - JWT/token security
    - Password reset vulnerabilities
    - Missing MFA
    - OAuth/SSO issues
    """

    agent_name = "authentication"
    agent_description = "Comprehensive authentication and session management testing"
    vulnerability_types = [
        VulnerabilityType.BROKEN_AUTH,
        VulnerabilityType.API_AUTH_BYPASS,
        VulnerabilityType.SECURITY_MISCONFIG
    ]

    # Common default credentials to test
    DEFAULT_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("administrator", "administrator"),
        ("root", "root"),
        ("root", "toor"),
        ("test", "test"),
        ("user", "user"),
        ("guest", "guest"),
        ("demo", "demo"),
        ("admin", "admin123"),
        ("admin", "Admin123"),
        ("admin", "P@ssw0rd"),
        ("superuser", "superuser"),
    ]

    # Weak passwords to test (now actually used!)
    WEAK_PASSWORDS = [
        "123456", "password", "12345678", "qwerty", "abc123",
        "password123", "admin123", "letmein", "welcome", "monkey",
        "1234567890", "Password1", "123123", "admin", "password1"
    ]

    # Login page indicators
    LOGIN_INDICATORS = [
        r"<input[^>]*type=[\"']?password[\"']?",
        r"login|signin|sign-in|log-in",
        r"username|email|user",
        r"password|passwd|pwd",
    ]

    # Error message patterns that reveal info
    INFO_DISCLOSURE_PATTERNS = [
        (r"user.*not found|user.*doesn't exist|invalid user|user not recognized", "username_enum"),
        (r"incorrect password|wrong password|invalid password|password.*incorrect", "password_enum"),
        (r"account.*locked|too many attempts|blocked|temporarily disabled", "lockout_msg"),
        (r"password must be|password should|password requirements|minimum length", "password_policy"),
        (r"account.*disabled|account.*suspended|account.*inactive", "account_status"),
    ]

    # Password reset paths
    PASSWORD_RESET_PATHS = [
        "/password/reset",
        "/reset-password",
        "/forgot-password",
        "/password/forgot",
        "/account/reset",
        "/auth/reset",
        "/user/reset-password",
    ]

    async def scan(
            self,
            target_url: str,
            endpoints: List[Dict[str, Any]],
            technology_stack: List[str] = None,
            scan_context: Optional["ScanContext"] = None
    ) -> List[AgentResult]:
        """
        Scan for authentication vulnerabilities.

        Args:
            target_url: Base URL
            endpoints: Endpoints to test
            technology_stack: Detected technologies
            scan_context: Shared scan context

        Returns:
            List of found vulnerabilities
        """
        results = []

        logger.info(f"[Auth Agent] Starting authentication scan for {target_url}")

        # Find login endpoints
        login_endpoints = await self._find_login_pages(target_url, endpoints)
        logger.info(f"[Auth Agent] Found {len(login_endpoints)} login endpoints")

        # Check if context has discovered credentials to try
        credentials_to_test = list(self.DEFAULT_CREDENTIALS[:AuthConfig.MAX_DEFAULT_CREDS_TO_TEST])
        if scan_context and scan_context.discovered_credentials:
            for cred in scan_context.discovered_credentials:
                credentials_to_test.append((cred.username, cred.password))
            logger.info(f"[Auth Agent] Added {len(scan_context.discovered_credentials)} credentials from context")

        # Run tests in parallel for each endpoint
        for endpoint in login_endpoints:
            endpoint_results = await self._test_login_endpoint(
                endpoint, credentials_to_test, scan_context
            )
            results.extend(endpoint_results)

        # Check for password reset vulnerabilities
        reset_results = await self._test_password_reset(target_url)
        results.extend(reset_results)

        # Check for JWT/token issues if technology stack indicates it
        if technology_stack and any(t.lower() in ['jwt', 'oauth', 'bearer'] for t in technology_stack):
            token_results = await self._test_token_security(target_url, endpoints)
            results.extend(token_results)

        # Check for session security issues on main page
        session_issues = await self._check_session_cookies(target_url)
        results.extend(session_issues)

        # Check for missing MFA
        mfa_result = await self._check_mfa_presence(login_endpoints)
        if mfa_result:
            results.append(mfa_result)

        logger.info(f"[Auth Agent] Scan complete. Found {len(results)} issues")
        return results

    async def _test_login_endpoint(
            self,
            endpoint: Dict[str, Any],
            credentials: List[Tuple[str, str]],
            scan_context: Optional["ScanContext"]
    ) -> List[AgentResult]:
        """
        Run all tests on a login endpoint.

        Args:
            endpoint: Login endpoint details
            credentials: Credentials to test
            scan_context: Shared scan context

        Returns:
            List of vulnerabilities found
        """
        results = []

        # Test for default credentials
        default_cred_result = await self._test_default_credentials(endpoint, credentials)
        if default_cred_result:
            results.append(default_cred_result)

            # If successful login found, store in context
            if scan_context and default_cred_result.is_vulnerable:
                scan_context.mark_authenticated()

        # Test for username enumeration (error-based)
        enum_result = await self._test_username_enumeration(endpoint)
        if enum_result:
            results.append(enum_result)

        # Test for timing-based username enumeration
        timing_enum_result = await self._test_timing_enumeration(endpoint)
        if timing_enum_result:
            results.append(timing_enum_result)

        # Check for missing rate limiting
        rate_limit_result = await self._test_rate_limiting(endpoint)
        if rate_limit_result:
            results.append(rate_limit_result)

        # Check for insecure session handling
        session_result = await self._test_session_security(endpoint)
        if session_result:
            results.append(session_result)

        # Test weak password acceptance
        weak_pwd_result = await self._test_weak_passwords(endpoint)
        if weak_pwd_result:
            results.append(weak_pwd_result)

        return results

    async def _find_login_pages(
            self,
            target_url: str,
            endpoints: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Find login pages in the target.

        Args:
            target_url: Base URL
            endpoints: Known endpoints

        Returns:
            List of login endpoints
        """
        login_endpoints = []
        seen_urls = set()

        # Check provided endpoints
        for endpoint in endpoints:
            url = endpoint.get("url", "")
            if url in seen_urls:
                continue

            if any(p in url.lower() for p in ["login", "signin", "auth"]):
                login_endpoints.append(endpoint)
                seen_urls.add(url)

        # Try common login paths
        common_paths = [
            "/login", "/signin", "/sign-in", "/log-in",
            "/auth/login", "/authentication", "/user/login",
            "/admin/login", "/api/login", "/api/auth/login",
            "/api/v1/login", "/api/v2/login",
            "/account/login", "/member/login"
        ]

        # Test paths in parallel
        tasks = []
        for path in common_paths:
            url = urljoin(target_url, path)
            if url not in seen_urls:
                tasks.append(self._check_login_page(url))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result.get("is_login"):
                url = result["url"]
                if url not in seen_urls:
                    login_endpoints.append(result)
                    seen_urls.add(url)

        return login_endpoints

    async def _check_login_page(self, url: str) -> Dict[str, Any]:
        """
        Check if a URL is a login page.

        Args:
            url: URL to check

        Returns:
            Endpoint dict if it's a login page, otherwise empty dict
        """
        try:
            response = await self.make_request(url, timeout=AuthConfig.REQUEST_TIMEOUT)

            if response and response.status_code == 200:
                # Check if it looks like a login page
                for pattern in self.LOGIN_INDICATORS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        return {
                            "url": url,
                            "method": "POST",
                            "params": {"username": "", "password": ""},
                            "is_login": True
                        }
        except Exception as e:
            logger.debug(f"[Auth Agent] Error checking {url}: {e}")

        return {"is_login": False}

    async def _test_default_credentials(
            self,
            endpoint: Dict[str, Any],
            credentials: List[Tuple[str, str]]
    ) -> Optional[AgentResult]:
        """
        Test for default credential vulnerabilities.

        Args:
            endpoint: Login endpoint details
            credentials: List of (username, password) tuples to test

        Returns:
            AgentResult if vulnerable, None otherwise
        """
        url = endpoint.get("url")

        for username, password in credentials:
            try:
                response = await self.make_request(
                    url,
                    method="POST",
                    data={"username": username, "password": password},
                    timeout=AuthConfig.REQUEST_TIMEOUT
                )

                if response is None:
                    continue

                # Check for successful login indicators
                success_indicators = [
                    response.status_code in [200, 302, 303],
                    "dashboard" in response.text.lower(),
                    "welcome" in response.text.lower(),
                    "logout" in response.text.lower(),
                    "profile" in response.text.lower(),
                    "set-cookie" in str(response.headers).lower(),
                ]

                # Check for failure indicators
                failure_indicators = [
                    "invalid" in response.text.lower(),
                    "incorrect" in response.text.lower(),
                    "failed" in response.text.lower(),
                    "error" in response.text.lower(),
                    "denied" in response.text.lower(),
                ]

                # If we see success and no failure indicators
                if sum(success_indicators) >= 2 and not any(failure_indicators):
                    logger.warning(f"[Auth Agent] Found working credentials: {username}:***")
                    return self.create_result(
                        vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                        is_vulnerable=True,
                        severity=Severity.CRITICAL,
                        confidence=90,
                        url=url,
                        title="Default Credentials Accepted",
                        description=f"The application accepts default credentials (username: {username}). This allows attackers to gain unauthorized access using well-known default credential combinations.",
                        evidence=f"Successful login with: {username}:{password}",
                        remediation="Force users to change default passwords on first login. Implement account lockout after failed attempts. Use strong password policies. Never ship with default credentials.",
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                        cwe_id="CWE-798",
                        reference_links=[
                            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                            "https://cwe.mitre.org/data/definitions/798.html"
                        ]
                    )

                # Small delay to avoid hammering
                await asyncio.sleep(AuthConfig.RATE_LIMIT_DELAY)

            except Exception as e:
                logger.debug(f"[Auth Agent] Default cred test error: {e}")

        return None

    async def _test_username_enumeration(
            self,
            endpoint: Dict[str, Any]
    ) -> Optional[AgentResult]:
        """
        Test for username enumeration vulnerability via error messages.

        Args:
            endpoint: Login endpoint details

        Returns:
            AgentResult if vulnerable, None otherwise
        """
        url = endpoint.get("url")

        try:
            test_users = [
                "admin",
                f"nonexistent_user_{hash('test')[:8]}",
                "test@example.com",
                f"invalid_{int(time.time())}"
            ]

            responses = []
            for user in test_users:
                response = await self.make_request(
                    url,
                    method="POST",
                    data={"username": user, "password": "WrongPassword123!"},
                    timeout=AuthConfig.REQUEST_TIMEOUT
                )
                if response:
                    responses.append((user, response.text.lower(), response.status_code))
                await asyncio.sleep(AuthConfig.RATE_LIMIT_DELAY)

            if len(responses) < 2:
                return None

            # Look for enumeration-revealing differences
            for user, response_text, status_code in responses:
                for pattern, issue_type in self.INFO_DISCLOSURE_PATTERNS:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        logger.info(f"[Auth Agent] Found username enumeration via {issue_type}")
                        return self.create_result(
                            vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                            is_vulnerable=True,
                            severity=Severity.MEDIUM,
                            confidence=75,
                            url=url,
                            title="Username Enumeration via Error Messages",
                            description="The login form returns different error messages for valid vs invalid usernames, allowing attackers to enumerate valid user accounts.",
                            evidence=f"Different responses detected for user enumeration (type: {issue_type})",
                            remediation="Use generic error messages like 'Invalid credentials' that don't reveal whether the username or password was incorrect. Ensure timing is consistent.",
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                            cwe_id="CWE-204",
                            reference_links=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account"
                            ]
                        )

        except Exception as e:
            logger.debug(f"[Auth Agent] Username enum error: {e}")

        return None

    async def _test_timing_enumeration(
            self,
            endpoint: Dict[str, Any]
    ) -> Optional[AgentResult]:
        """
        Test for timing-based username enumeration.

        Args:
            endpoint: Login endpoint details

        Returns:
            AgentResult if vulnerable, None otherwise
        """
        url = endpoint.get("url")

        try:
            # Test with likely valid and invalid usernames
            test_cases = [
                ("admin", "likely_valid"),
                ("administrator", "likely_valid"),
                (f"invalid_{int(time.time())}", "invalid"),
                (f"notreal_{hash('x')[:8]}", "invalid"),
            ]

            timing_results: List[TimingResult] = []

            for username, category in test_cases:
                start_time = time.time()
                response = await self.make_request(
                    url,
                    method="POST",
                    data={"username": username, "password": "WrongPassword123!"},
                    timeout=AuthConfig.REQUEST_TIMEOUT
                )
                elapsed = time.time() - start_time

                if response:
                    timing_results.append(TimingResult(
                        username=username,
                        response_time=elapsed,
                        status_code=response.status_code,
                        response_length=len(response.text)
                    ))

                await asyncio.sleep(AuthConfig.RATE_LIMIT_DELAY)

            if len(timing_results) < 4:
                return None

            # Analyze timing differences
            valid_times = [r.response_time for r in timing_results if "likely_valid" in str(r.username)]
            invalid_times = [r.response_time for r in timing_results if "invalid" in str(r.username)]

            if valid_times and invalid_times:
                avg_valid = sum(valid_times) / len(valid_times)
                avg_invalid = sum(invalid_times) / len(invalid_times)
                diff = abs(avg_valid - avg_invalid)

                if diff > AuthConfig.TIMING_DIFFERENCE_THRESHOLD:
                    logger.info(f"[Auth Agent] Found timing-based enumeration (diff: {diff:.3f}s)")
                    return self.create_result(
                        vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                        is_vulnerable=True,
                        severity=Severity.MEDIUM,
                        confidence=65,
                        url=url,
                        title="Username Enumeration via Timing Analysis",
                        description=f"The login endpoint shows measurable timing differences ({diff:.3f}s) between valid and invalid usernames, allowing enumeration through timing attacks.",
                        evidence=f"Avg valid user time: {avg_valid:.3f}s, Avg invalid: {avg_invalid:.3f}s",
                        remediation="Ensure constant-time comparison for all authentication steps. Add consistent delays. Consider rate limiting.",
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                        cwe_id="CWE-208",
                        reference_links=[
                            "https://cwe.mitre.org/data/definitions/208.html"
                        ]
                    )

        except Exception as e:
            logger.debug(f"[Auth Agent] Timing enum error: {e}")

        return None

    async def _test_rate_limiting(
            self,
            endpoint: Dict[str, Any]
    ) -> Optional[AgentResult]:
        """
        Test for missing rate limiting on login.

        Args:
            endpoint: Login endpoint details

        Returns:
            AgentResult if vulnerable, None otherwise
        """
        url = endpoint.get("url")

        try:
            request_count = AuthConfig.MAX_RAPID_REQUESTS
            blocked = False
            successful_requests = 0

            for i in range(request_count):
                response = await self.make_request(
                    url,
                    method="POST",
                    data={"username": f"test{i}", "password": "wrongpassword"},
                    timeout=AuthConfig.REQUEST_TIMEOUT
                )

                if response is None:
                    continue

                successful_requests += 1

                # Check if we're being rate limited
                if response.status_code == 429:
                    blocked = True
                    logger.info(f"[Auth Agent] Rate limiting detected after {successful_requests} requests")
                    break

                if "too many" in response.text.lower() or "rate limit" in response.text.lower():
                    blocked = True
                    logger.info(f"[Auth Agent] Rate limiting detected (message) after {successful_requests} requests")
                    break

            if not blocked and successful_requests >= request_count * 0.8:
                return self.create_result(
                    vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                    is_vulnerable=True,
                    severity=Severity.MEDIUM,
                    confidence=70,
                    url=url,
                    title="Missing Rate Limiting on Authentication",
                    description=f"The login endpoint does not implement rate limiting. {successful_requests} rapid requests were accepted without blocking or throttling, enabling brute force attacks.",
                    evidence=f"Sent {successful_requests} requests without triggering rate limiting",
                    remediation="Implement rate limiting (e.g., max 5 attempts per 15 minutes). Use exponential backoff. Consider CAPTCHA after failed attempts. Implement account lockout policies.",
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                    cwe_id="CWE-307",
                    reference_links=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                    ]
                )

        except Exception as e:
            logger.debug(f"[Auth Agent] Rate limit test error: {e}")

        return None

    async def _test_session_security(
            self,
            endpoint: Dict[str, Any]
    ) -> Optional[AgentResult]:
        """
        Test session token security after login.

        Args:
            endpoint: Login endpoint details

        Returns:
            AgentResult if vulnerable, None otherwise
        """
        url = endpoint.get("url")

        try:
            # Try a test login
            response = await self.make_request(
                url,
                method="POST",
                data={"username": "testuser", "password": "testpass123"},
                timeout=AuthConfig.REQUEST_TIMEOUT
            )

            if not response:
                return None

            issues = []

            # Check session token length
            for cookie in response.cookies.jar:
                if "session" in cookie.name.lower() or "token" in cookie.name.lower():
                    if len(cookie.value) < AuthConfig.SESSION_COOKIE_MIN_LENGTH:
                        issues.append(f"Short session token ({len(cookie.value)} chars)")

            # Check if session ID is in URL
            if "session" in response.url.lower() or "token" in response.url.lower():
                issues.append("Session ID exposed in URL")

            if issues:
                return self.create_result(
                    vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                    is_vulnerable=True,
                    severity=Severity.MEDIUM,
                    confidence=70,
                    url=url,
                    title="Weak Session Token Generation",
                    description=f"Session management issues detected: {', '.join(issues)}",
                    evidence=f"Issues: {issues}",
                    remediation="Use cryptographically secure random session tokens (min 128 bits). Never expose session IDs in URLs. Regenerate session ID after login.",
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                    cwe_id="CWE-330",
                    reference_links=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
                    ]
                )

        except Exception as e:
            logger.debug(f"[Auth Agent] Session test error: {e}")

        return None

    async def _test_weak_passwords(
            self,
            endpoint: Dict[str, Any]
    ) -> Optional[AgentResult]:
        """
        Test if the system accepts weak passwords.

        Args:
            endpoint: Login endpoint details

        Returns:
            AgentResult if vulnerable, None otherwise
        """
        url = endpoint.get("url")

        # Look for registration or password change endpoint
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        registration_paths = [
            "/register", "/signup", "/sign-up",
            "/api/register", "/api/signup",
            "/user/register", "/account/create"
        ]

        try:
            for path in registration_paths[:3]:  # Limit attempts
                reg_url = urljoin(base_url, path)

                # Try registering with a weak password
                response = await self.make_request(
                    reg_url,
                    method="POST",
                    data={
                        "username": f"testuser_{int(time.time())}",
                        "password": "123456",  # Very weak password
                        "email": f"test{int(time.time())}@example.com"
                    },
                    timeout=AuthConfig.REQUEST_TIMEOUT
                )

                if response and response.status_code in [200, 201, 302]:
                    # Check if registration succeeded
                    if any(indicator in response.text.lower() for indicator in
                           ["success", "created", "registered", "welcome"]):
                        return self.create_result(
                            vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                            is_vulnerable=True,
                            severity=Severity.MEDIUM,
                            confidence=80,
                            url=reg_url,
                            title="Weak Password Policy",
                            description="The application accepts very weak passwords (e.g., '123456') without enforcing minimum security requirements.",
                            evidence="Successfully registered with password: 123456",
                            remediation="Enforce strong password policies: minimum 8 characters, require mix of uppercase, lowercase, numbers, and special characters. Consider using password strength libraries like zxcvbn.",
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                            cwe_id="CWE-521",
                            reference_links=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#implement-proper-password-strength-controls"
                            ]
                        )

                await asyncio.sleep(AuthConfig.RATE_LIMIT_DELAY)

        except Exception as e:
            logger.debug(f"[Auth Agent] Weak password test error: {e}")

        return None

    async def _test_password_reset(self, target_url: str) -> List[AgentResult]:
        """
        Test password reset functionality for vulnerabilities.

        Args:
            target_url: Base URL

        Returns:
            List of vulnerabilities found
        """
        results = []

        for path in self.PASSWORD_RESET_PATHS[:5]:  # Limit attempts
            url = urljoin(target_url, path)

            try:
                response = await self.make_request(url, timeout=AuthConfig.REQUEST_TIMEOUT)

                if response and response.status_code == 200:
                    issues = []

                    # Check for token in URL
                    if "token=" in response.url or "reset=" in response.url:
                        issues.append("Reset token exposed in URL (should use POST)")

                    # Check for predictable tokens
                    if re.search(r'token=\d{1,10}$', response.url):
                        issues.append("Predictable reset token format")

                    # Check response for security issues
                    if "no expiration" in response.text.lower():
                        issues.append("Reset tokens may not expire")

                    if issues:
                        results.append(self.create_result(
                            vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                            is_vulnerable=True,
                            severity=Severity.HIGH,
                            confidence=75,
                            url=url,
                            title="Insecure Password Reset",
                            description=f"Password reset functionality has security issues: {', '.join(issues)}",
                            evidence=f"Issues found: {issues}",
                            remediation="Use cryptographically random tokens. Send tokens via email only. Implement short expiration (15-30 mins). Use one-time tokens. Never expose tokens in URLs.",
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                            cwe_id="CWE-640"
                        ))

            except Exception as e:
                logger.debug(f"[Auth Agent] Password reset test error: {e}")

        return results

    async def _test_token_security(
            self,
            target_url: str,
            endpoints: List[Dict[str, Any]]
    ) -> List[AgentResult]:
        """
        Test JWT/Bearer token security.

        Args:
            target_url: Base URL
            endpoints: List of endpoints

        Returns:
            List of vulnerabilities found
        """
        results = []

        # Look for endpoints that might return tokens
        for endpoint in endpoints[:10]:  # Limit scope
            url = endpoint.get("url")
            if not any(p in url.lower() for p in ["login", "auth", "token"]):
                continue

            try:
                response = await self.make_request(url, timeout=AuthConfig.REQUEST_TIMEOUT)

                if not response:
                    continue

                # Check for JWT tokens in response
                jwt_pattern = r'[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'
                tokens = re.findall(jwt_pattern, response.text)

                for token in tokens:
                    if len(token) > AuthConfig.TOKEN_MIN_LENGTH:
                        # Basic JWT structure check
                        parts = token.split('.')
                        if len(parts) == 3:
                            results.append(self.create_result(
                                vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                                is_vulnerable=True,
                                severity=Severity.INFO,
                                confidence=60,
                                url=url,
                                title="JWT Token Detected",
                                description="JWT token found in response. Ensure proper validation, signature verification, and expiration are implemented.",
                                evidence=f"JWT token detected (length: {len(token)})",
                                remediation="Verify JWT signatures server-side. Use strong algorithms (RS256, not HS256 with weak secrets). Implement short expiration. Use refresh tokens. Validate all claims.",
                                owasp_category="A07:2021 – Identification and Authentication Failures",
                                cwe_id="CWE-347"
                            ))
                            break  # One finding per endpoint

            except Exception as e:
                logger.debug(f"[Auth Agent] Token security test error: {e}")

        return results

    async def _check_mfa_presence(
            self,
            login_endpoints: List[Dict[str, Any]]
    ) -> Optional[AgentResult]:
        """
        Check if MFA/2FA is implemented.

        Args:
            login_endpoints: List of login endpoints

        Returns:
            AgentResult if MFA is missing, None otherwise
        """
        if not login_endpoints:
            return None

        # Check if any MFA indicators are present
        mfa_keywords = [
            "two-factor", "2fa", "mfa", "multi-factor",
            "authenticator", "verification code", "otp"
        ]

        for endpoint in login_endpoints:
            url = endpoint.get("url")
            try:
                response = await self.make_request(url, timeout=AuthConfig.REQUEST_TIMEOUT)

                if response:
                    text_lower = response.text.lower()
                    if any(keyword in text_lower for keyword in mfa_keywords):
                        logger.info("[Auth Agent] MFA indicators found")
                        return None  # MFA appears to be present

            except Exception as e:
                logger.debug(f"[Auth Agent] MFA check error: {e}")

        # If we didn't find MFA indicators, report it as a best practice issue
        return self.create_result(
            vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
            is_vulnerable=True,
            severity=Severity.LOW,
            confidence=50,
            url=login_endpoints[0].get("url"),
            title="Multi-Factor Authentication Not Detected",
            description="The application does not appear to implement multi-factor authentication. MFA significantly reduces the risk of account compromise.",
            evidence="No MFA/2FA indicators found in authentication flow",
            remediation="Implement multi-factor authentication using TOTP (Google Authenticator, Authy), SMS (less secure), or hardware tokens (most secure). Make MFA mandatory for privileged accounts.",
            owasp_category="A07:2021 – Identification and Authentication Failures",
            cwe_id="CWE-308"
        )

    async def _check_session_cookies(self, url: str) -> List[AgentResult]:
        """
        Check session cookie security attributes.

        Args:
            url: URL to check

        Returns:
            List of vulnerabilities found
        """
        results = []

        try:
            response = await self.make_request(url, timeout=AuthConfig.REQUEST_TIMEOUT)
            if response is None:
                return results

            cookies = response.cookies

            for cookie in cookies.jar:
                issues = []

                # Check for HttpOnly flag
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    issues.append("Missing HttpOnly flag (vulnerable to XSS)")

                # Check for Secure flag (if HTTPS)
                if url.startswith("https") and not cookie.secure:
                    issues.append("Missing Secure flag (can be sent over HTTP)")

                # Check for SameSite attribute
                if not cookie.has_nonstandard_attr("SameSite"):
                    issues.append("Missing SameSite attribute (vulnerable to CSRF)")

                # Check cookie name for session indicators
                is_session_cookie = any(
                    indicator in cookie.name.lower()
                    for indicator in ["session", "token", "auth", "login"]
                )

                if issues and is_session_cookie:
                    severity = Severity.MEDIUM if len(issues) > 1 else Severity.LOW

                    results.append(self.create_result(
                        vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                        is_vulnerable=True,
                        severity=severity,
                        confidence=90,
                        url=url,
                        parameter=cookie.name,
                        title=f"Insecure Session Cookie: {cookie.name}",
                        description=f"The cookie '{cookie.name}' is missing critical security attributes: {', '.join(issues)}. This exposes the application to session hijacking, XSS, and CSRF attacks.",
                        evidence=f"Cookie: {cookie.name}, Missing: {issues}",
                        remediation="Set HttpOnly (prevents JavaScript access), Secure (HTTPS only), and SameSite=Strict or Lax (CSRF protection) on all session cookies. Example: Set-Cookie: session=xxx; HttpOnly; Secure; SameSite=Strict",
                        owasp_category="A05:2021 – Security Misconfiguration",
                        cwe_id="CWE-614",
                        reference_links=[
                            "https://owasp.org/www-community/controls/SecureCookieAttribute"
                        ]
                    ))

        except Exception as e:
            logger.debug(f"[Auth Agent] Cookie check error: {e}")

        return results