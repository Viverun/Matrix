"""
Authentication Security Agent - Tests authentication mechanisms.
"""
from typing import List, Dict, Any, Optional, TYPE_CHECKING
import re
from urllib.parse import urljoin

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType

if TYPE_CHECKING:
    from core.scan_context import ScanContext


class AuthenticationAgent(BaseSecurityAgent):
    """
    Authentication testing agent.
    
    Tests for authentication vulnerabilities:
    - Weak password policies
    - Default credentials
    - Session management issues
    - Brute force susceptibility
    - Password hints/errors that reveal info
    """
    
    agent_name = "authentication"
    agent_description = "Tests authentication mechanisms and session management"
    vulnerability_types = [VulnerabilityType.BROKEN_AUTH, VulnerabilityType.AUTH_BYPASS]
    
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
    ]
    
    # Weak passwords to test
    WEAK_PASSWORDS = [
        "123456",
        "password",
        "12345678",
        "qwerty",
        "abc123",
        "password123",
        "admin123",
        "letmein",
        "welcome",
        "monkey",
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
        (r"user.*not found|user.*doesn't exist|invalid user", "username_enum"),
        (r"incorrect password|wrong password|invalid password", "password_enum"),
        (r"account.*locked|too many attempts|blocked", "lockout_msg"),
        (r"password must be|password should|password requirements", "password_policy"),
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
        
        # Find login endpoints
        login_endpoints = await self._find_login_pages(target_url, endpoints)
        
        # Check if context has discovered credentials to try
        credentials_to_test = list(self.DEFAULT_CREDENTIALS)
        if scan_context and scan_context.discovered_credentials:
            for cred in scan_context.discovered_credentials:
                credentials_to_test.append((cred.username, cred.password))
            print(f"[Auth Agent] Added {len(scan_context.discovered_credentials)} credentials from context")
        
        for endpoint in login_endpoints:
            # Test for default credentials
            default_cred_result = await self._test_default_credentials(endpoint)
            if default_cred_result:
                results.append(default_cred_result)
                
                # If successful login found, store in context
                if scan_context and default_cred_result.is_vulnerable:
                    scan_context.mark_authenticated()
            
            # Test for username enumeration
            enum_result = await self._test_username_enumeration(endpoint)
            if enum_result:
                results.append(enum_result)
            
            # Check for missing rate limiting
            rate_limit_result = await self._test_rate_limiting(endpoint)
            if rate_limit_result:
                results.append(rate_limit_result)
            
            # Check for insecure session handling
            session_result = await self._test_session_security(endpoint)
            if session_result:
                results.append(session_result)
        
        # Check for session security issues on main page
        session_issues = await self._check_session_cookies(target_url)
        results.extend(session_issues)
        
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
        
        # Check provided endpoints
        for endpoint in endpoints:
            url = endpoint.get("url", "")
            if any(p in url.lower() for p in ["login", "signin", "auth"]):
                login_endpoints.append(endpoint)
        
        # Try common login paths
        common_paths = [
            "/login",
            "/signin",
            "/auth/login",
            "/user/login",
            "/admin/login",
            "/api/login",
            "/api/auth/login",
        ]
        
        for path in common_paths:
            url = urljoin(target_url, path)
            response = await self.make_request(url)
            
            if response and response.status_code == 200:
                # Check if it looks like a login page
                for pattern in self.LOGIN_INDICATORS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        login_endpoints.append({
                            "url": url,
                            "method": "POST",
                            "params": {"username": "", "password": ""}
                        })
                        break
        
        return login_endpoints
    
    async def _test_default_credentials(
        self,
        endpoint: Dict[str, Any]
    ) -> AgentResult | None:
        """
        Test for default credential vulnerabilities.
        
        Args:
            endpoint: Login endpoint details
            
        Returns:
            AgentResult if vulnerable, None otherwise
        """
        url = endpoint.get("url")
        
        for username, password in self.DEFAULT_CREDENTIALS[:5]:  # Limit tests
            try:
                response = await self.make_request(
                    url,
                    method="POST",
                    data={"username": username, "password": password}
                )
                
                if response is None:
                    continue
                
                # Check for successful login indicators
                success_indicators = [
                    response.status_code in [200, 302, 303],
                    "dashboard" in response.text.lower(),
                    "welcome" in response.text.lower(),
                    "logout" in response.text.lower(),
                    "set-cookie" in str(response.headers).lower(),
                ]
                
                # Check for failure indicators
                failure_indicators = [
                    "invalid" in response.text.lower(),
                    "incorrect" in response.text.lower(),
                    "failed" in response.text.lower(),
                    "error" in response.text.lower(),
                ]
                
                # If we see success and no failure indicators
                if any(success_indicators) and not any(failure_indicators):
                    return self.create_result(
                        vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                        is_vulnerable=True,
                        severity=Severity.CRITICAL,
                        confidence=90,
                        url=url,
                        title="Default Credentials Accepted",
                        description=f"The application accepts default credentials ({username}:{password}). This allows attackers to gain unauthorized access using well-known default credential combinations.",
                        evidence=f"Credentials: {username}:{password}",
                        remediation="Force users to change default passwords on first login. Implement account lockout after failed attempts. Use strong password policies.",
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                        cwe_id="CWE-798",
                        reference_links=[
                            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                            "https://cwe.mitre.org/data/definitions/798.html"
                        ]
                    )
                
            except Exception as e:
                print(f"[Auth Agent] Default cred test error: {e}")
        
        return None
    
    async def _test_username_enumeration(
        self,
        endpoint: Dict[str, Any]
    ) -> AgentResult | None:
        """
        Test for username enumeration vulnerability.
        
        Args:
            endpoint: Login endpoint details
            
        Returns:
            AgentResult if vulnerable, None otherwise
        """
        url = endpoint.get("url")
        
        try:
            # Test with valid-looking and invalid usernames
            responses = []
            
            test_users = [
                "admin",
                "nonexistent_user_xyz123",
                "test@test.com",
                "definitely_not_a_user_" + str(hash("test"))[:8]
            ]
            
            for user in test_users:
                response = await self.make_request(
                    url,
                    method="POST",
                    data={"username": user, "password": "wrongpassword123"}
                )
                if response:
                    responses.append((user, response.text.lower()))
            
            if len(responses) < 2:
                return None
            
            # Check if responses differ in revealing ways
            messages = [r[1] for r in responses]
            
            # Look for enumeration-revealing differences
            for response_text in messages:
                for pattern, issue_type in self.INFO_DISCLOSURE_PATTERNS:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return self.create_result(
                            vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                            is_vulnerable=True,
                            severity=Severity.MEDIUM,
                            confidence=75,
                            url=url,
                            title="Username Enumeration via Error Messages",
                            description="The login form returns different error messages for valid vs invalid usernames, allowing attackers to enumerate valid user accounts.",
                            evidence=f"Different responses detected for user enumeration ({issue_type})",
                            remediation="Use generic error messages like 'Invalid credentials' that don't reveal whether the username or password was incorrect.",
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                            cwe_id="CWE-204",
                            reference_links=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account"
                            ]
                        )
            
        except Exception as e:
            print(f"[Auth Agent] Username enum error: {e}")
        
        return None
    
    async def _test_rate_limiting(
        self,
        endpoint: Dict[str, Any]
    ) -> AgentResult | None:
        """
        Test for missing rate limiting on login.
        
        Args:
            endpoint: Login endpoint details
            
        Returns:
            AgentResult if vulnerable, None otherwise
        """
        url = endpoint.get("url")
        
        try:
            # Make several rapid requests
            request_count = 10
            blocked = False
            
            for i in range(request_count):
                response = await self.make_request(
                    url,
                    method="POST",
                    data={"username": f"test{i}", "password": "wrongpassword"}
                )
                
                if response is None:
                    continue
                
                # Check if we're being rate limited
                if response.status_code == 429:
                    blocked = True
                    break
                
                if "too many" in response.text.lower() or "rate limit" in response.text.lower():
                    blocked = True
                    break
            
            if not blocked:
                return self.create_result(
                    vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                    is_vulnerable=True,
                    severity=Severity.MEDIUM,
                    confidence=70,
                    url=url,
                    title="Missing Rate Limiting on Authentication",
                    description=f"The login endpoint does not appear to implement rate limiting. {request_count} rapid requests were accepted without any blocking or throttling.",
                    evidence=f"Sent {request_count} requests without triggering rate limiting",
                    remediation="Implement rate limiting on authentication endpoints. Use exponential backoff. Consider CAPTCHA after failed attempts. Implement account lockout policies.",
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                    cwe_id="CWE-307",
                    reference_links=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                    ]
                )
            
        except Exception as e:
            print(f"[Auth Agent] Rate limit test error: {e}")
        
        return None
    
    async def _test_session_security(
        self,
        endpoint: Dict[str, Any]
    ) -> AgentResult | None:
        """Test session cookie security."""
        # Implementation for session testing
        return None
    
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
            response = await self.make_request(url)
            if response is None:
                return results
            
            cookies = response.cookies
            
            for cookie in cookies.jar:
                issues = []
                
                # Check for HttpOnly flag
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    issues.append("Missing HttpOnly flag")
                
                # Check for Secure flag (if HTTPS)
                if url.startswith("https") and not cookie.secure:
                    issues.append("Missing Secure flag")
                
                # Check for SameSite attribute
                if not cookie.has_nonstandard_attr("SameSite"):
                    issues.append("Missing SameSite attribute")
                
                if issues:
                    results.append(self.create_result(
                        vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                        is_vulnerable=True,
                        severity=Severity.LOW,
                        confidence=90,
                        url=url,
                        title=f"Insecure Cookie: {cookie.name}",
                        description=f"The cookie '{cookie.name}' is missing security attributes: {', '.join(issues)}",
                        evidence=f"Cookie: {cookie.name}, Issues: {issues}",
                        remediation="Set HttpOnly, Secure (for HTTPS), and SameSite=Strict or SameSite=Lax attributes on all session cookies.",
                        owasp_category="A05:2021 – Security Misconfiguration",
                        cwe_id="CWE-614"
                    ))
            
        except Exception as e:
            print(f"[Auth Agent] Cookie check error: {e}")
        
        return results
