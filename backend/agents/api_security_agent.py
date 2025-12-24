"""
API Security Agent - Tests REST API security.
"""
from typing import List, Dict, Any, Optional
import re
import json
from urllib.parse import urljoin

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType


class APISecurityAgent(BaseSecurityAgent):
    """
    API Security testing agent.
    
    Tests for API vulnerabilities:
    - Broken Object Level Authorization (BOLA/IDOR)
    - Excessive Data Exposure
    - Missing Rate Limiting
    - Improper Input Validation
    - Security Misconfigurations
    """
    
    agent_name = "api_security"
    agent_description = "Tests API endpoint security"
    vulnerability_types = [
        VulnerabilityType.IDOR,
        VulnerabilityType.SENSITIVE_DATA,
        VulnerabilityType.BROKEN_ACCESS,
        VulnerabilityType.SECURITY_MISCONFIG
    ]
    
    # Common API paths to discover
    API_PATHS = [
        "/api",
        "/api/v1",
        "/api/v2",
        "/rest",
        "/graphql",
        "/api/users",
        "/api/admin",
        "/api/config",
        "/api/settings",
        "/.env",
        "/config.json",
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
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
    ]
    
    # Security headers to check
    # Removed X-XSS-Protection (deprecated) and ACAO (has dedicated test)
    SECURITY_HEADERS = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
    ]
    
    async def scan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str] = None,
        scan_context: Optional[Any] = None
    ) -> List[AgentResult]:
        """
        Scan for API security vulnerabilities.
        
        Args:
            target_url: Base URL
            endpoints: Endpoints to test
            technology_stack: Detected technologies
            
        Returns:
            List of found vulnerabilities
        """
        results = []
        
        # Discover API endpoints
        api_endpoints = await self._discover_api_endpoints(target_url)
        all_endpoints = endpoints + api_endpoints
        
        for endpoint in all_endpoints:
            url = endpoint.get("url", target_url)
            
            # Test for sensitive data exposure
            data_exposure = await self._test_data_exposure(url)
            if data_exposure:
                results.append(data_exposure)
            
            # Test for IDOR
            idor_result = await self._test_idor(endpoint)
            if idor_result:
                results.append(idor_result)
        
        # Check security headers
        header_issues = await self._check_security_headers(target_url)
        results.extend(header_issues)
        
        # Check for exposed configuration
        config_issues = await self._check_exposed_configs(target_url)
        results.extend(config_issues)
        
        # Check CORS configuration
        cors_result = await self._test_cors(target_url)
        if cors_result:
            results.append(cors_result)
        
        return results
    
    async def _discover_api_endpoints(
        self,
        target_url: str
    ) -> List[Dict[str, Any]]:
        """
        Discover API endpoints.
        
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
            # Remove leading slash if present to avoid absolute path joining
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
            except:
                pass
        
        return endpoints
    
    async def _test_data_exposure(self, url: str) -> AgentResult | None:
        """
        Test for excessive data exposure.
        
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
                    vulnerability_type="Sensitive Data Exposure",
                    context=f"API response contains potential sensitive data: {unique_types}",
                    response_data=response_text[:1500]
                )
                
                severity = Severity.HIGH if any(
                    t in ["password", "secret", "api_key", "ssn", "credit_card"]
                    for t in unique_types
                ) else Severity.MEDIUM
                
                return self.create_result(
                    vulnerability_type=VulnerabilityType.SENSITIVE_DATA,
                    is_vulnerable=True,
                    severity=severity,
                    confidence=ai_analysis.get("confidence", 75),
                    url=url,
                    title="Sensitive Data Exposure in API Response",
                    description=f"The API endpoint exposes potentially sensitive data in its response. Detected data types: {', '.join(unique_types)}",
                    evidence=f"Sensitive data types found: {unique_types}",
                    ai_analysis=ai_analysis.get("reason", ""),
                    remediation="Review API responses and remove unnecessary sensitive fields. Implement field-level access control. Use DTOs to control what data is exposed.",
                    owasp_category="A01:2021 – Broken Access Control",
                    cwe_id="CWE-200",
                    reference_links=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"
                    ]
                )
            
        except Exception as e:
            print(f"[API Agent] Data exposure test error: {e}")
        
        return None
    
    async def _test_idor(self, endpoint: Dict[str, Any]) -> AgentResult | None:
        """
        Test for Insecure Direct Object Reference (IDOR).
        
        Args:
            endpoint: Endpoint to test
            
        Returns:
            AgentResult if vulnerable, None otherwise
        """
        url = endpoint.get("url", "")
        
        # Check if URL contains numeric ID patterns
        id_pattern = r'/(\d+)(?:/|$|\?)'
        match = re.search(id_pattern, url)
        
        if not match:
            return None
        
        original_id = match.group(1)
        
        try:
            # Get original resource
            original_response = await self.make_request(url)
            if original_response is None or original_response.status_code != 200:
                return None
            
            # Try accessing other IDs
            test_ids = [
                str(int(original_id) + 1),
                str(int(original_id) - 1),
                "1",
                "0",
                str(int(original_id) * 2),
            ]
            
            for test_id in test_ids:
                test_url = url.replace(f"/{original_id}", f"/{test_id}")
                
                if test_url == url:
                    continue
                
                response = await self.make_request(test_url)
                
                if response and response.status_code == 200:
                    # Check if we got different data
                    if response.text != original_response.text:
                        return self.create_result(
                            vulnerability_type=VulnerabilityType.IDOR,
                            is_vulnerable=True,
                            severity=Severity.HIGH,
                            confidence=80,
                            url=url,
                            title="Insecure Direct Object Reference (IDOR)",
                            description=f"The API allows accessing resources by manipulating the object ID. Changing the ID from {original_id} to {test_id} returned a different resource, indicating missing authorization checks.",
                            evidence=f"Original ID: {original_id}, Test ID: {test_id} - Both accessible",
                            remediation="Implement proper authorization checks. Verify that the authenticated user has permission to access the requested resource. Use indirect references or UUIDs instead of sequential IDs.",
                            owasp_category="A01:2021 – Broken Access Control",
                            cwe_id="CWE-639",
                            reference_links=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                            ]
                        )
            
        except Exception as e:
            print(f"[API Agent] IDOR test error: {e}")
        
        return None
    
    def _validate_header_value(
        self, 
        header: str, 
        value: str, 
        url: str
    ) -> tuple[bool, AgentResult | None]:
        """
        Validate that a security header is correctly configured.
        
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
                    description=f"Header value '{value}' is not the recommended 'nosniff'.",
                    evidence=f"X-Content-Type-Options: {value}",
                    likelihood=1.0,
                    impact=1.0,
                    exploitability_rationale="Minor misconfiguration. The header is present but not optimally configured.",
                    remediation="Set X-Content-Type-Options to 'nosniff'.",
                    owasp_category="A05:2021 – Security Misconfiguration",
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
                    description=f"Header value '{value}' may allow unintended framing. Recommended values are 'DENY' or 'SAMEORIGIN'.",
                    evidence=f"X-Frame-Options: {value}",
                    likelihood=2.0,
                    impact=3.0,
                    exploitability_rationale="Potential clickjacking vector if value allows framing from untrusted origins. Still requires social engineering for exploitation.",
                    remediation="Set X-Frame-Options to 'DENY' (most restrictive) or 'SAMEORIGIN'.",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    cwe_id="CWE-1021"
                )
            return True, None
        
        # HSTS validation
        if header_lower == "strict-transport-security":
            # Check for reasonable max-age (at least 6 months = 15768000 seconds)
            import re
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
                        description=f"HSTS max-age of {max_age} seconds ({max_age // 86400} days) is below the recommended minimum of 6 months.",
                        evidence=f"Strict-Transport-Security: {value}",
                        likelihood=1.0,
                        impact=2.0,
                        exploitability_rationale="Short HSTS duration increases window for SSL stripping attacks after cache expiry. Not directly exploitable.",
                        remediation="Set max-age to at least 31536000 (1 year). Consider adding 'includeSubDomains' if all subdomains support HTTPS.",
                        owasp_category="A05:2021 – Security Misconfiguration",
                        cwe_id="CWE-319"
                    )
            return True, None
        
        # CSP validation - check for overly permissive directives
        if header_lower == "content-security-policy":
            issues = []
            if "'unsafe-inline'" in value_lower and "script-src" in value_lower:
                issues.append("script-src allows 'unsafe-inline'")
            if "'unsafe-eval'" in value_lower:
                issues.append("allows 'unsafe-eval'")
            if "default-src *" in value_lower or "default-src '*'" in value_lower:
                issues.append("default-src allows all sources (*)")
            
            if issues:
                return False, self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.LOW,
                    confidence=90,
                    url=url,
                    title="Content-Security-Policy Too Permissive",
                    description=f"CSP contains permissive directives that reduce its effectiveness: {', '.join(issues)}.",
                    evidence=f"Content-Security-Policy: {value[:200]}...",
                    likelihood=3.0,
                    impact=3.0,
                    exploitability_rationale="Permissive CSP reduces defense-in-depth against XSS. Still requires an XSS vulnerability to exploit.",
                    remediation="Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes for inline scripts. Restrict default-src.",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    cwe_id="CWE-693"
                )
            return True, None
        
        # Default: header present, assume valid
        return True, None

    async def _check_security_headers(self, url: str) -> List[AgentResult]:
        """
        Check for missing or misconfigured security headers.
        
        Acknowledges correctly configured headers and only flags issues
        with appropriate severity based on risk amplification potential.
        
        Args:
            url: URL to check
            
        Returns:
            List of security header issues (Low/Informational unless chained)
        """
        results = []
        present_headers = []
        
        try:
            response = await self.make_request(url)
            if response is None:
                return results
            
            headers = response.headers
            headers_lower = {h.lower(): v for h, v in headers.items()}
            
            # Track which headers are present and correctly configured
            for header in self.SECURITY_HEADERS:
                header_lower = header.lower()
                
                if header_lower in headers_lower:
                    # Header is present - validate configuration
                    value = headers_lower[header_lower]
                    is_valid, issue = self._validate_header_value(header, value, url)
                    
                    if is_valid:
                        present_headers.append(header)
                    elif issue:
                        results.append(issue)
                else:
                    # Header is missing
                    # Specific logic for HSTS: only flag on HTTPS
                    if header == "Strict-Transport-Security" and not url.startswith("https"):
                        continue  # Not applicable on HTTP - this is correct behavior
                        
                    # Default risk values - Low/Informational for standalone missing headers
                    severity = Severity.LOW
                    likelihood = 2.0  # Low - requires chaining for exploitation
                    impact = 2.0
                    cwe_id = "CWE-693"
                    title = f"Missing Security Header: {header}"
                    rationale = (
                        "This missing header increases attack surface but is NOT directly exploitable alone. "
                        "Risk is conditional: exploitation requires chaining with another vulnerability "
                        "(e.g., missing CSP is only critical when combined with XSS)."
                    )
                    
                    if header == "X-Frame-Options":
                        cwe_id = "CWE-1021"
                        rationale = (
                            "Missing X-Frame-Options allows embedding in iframes, enabling potential clickjacking. "
                            "However, exploitation requires a targeted social engineering attack and user interaction. "
                            "Not directly exploitable without additional attack vectors."
                        )
                    elif header == "Content-Security-Policy":
                        impact = 3.0  # Slightly higher as it's a key defense-in-depth control
                        rationale = (
                            "Missing CSP removes a defense-in-depth layer against XSS. "
                            "This amplifies risk IF an XSS vulnerability exists, but is not exploitable alone. "
                            "Severity escalates only when correlated with confirmed XSS findings."
                        )
                        
                    results.append(self.create_result(
                        vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                        is_vulnerable=True,
                        severity=severity,
                        confidence=95,
                        url=url,
                        title=title,
                        description=f"The {header} header is not present. This is a defense-in-depth control that reduces attack surface when properly configured.",
                        evidence=f"Header '{header}' not found in response headers",
                        likelihood=likelihood,
                        impact=impact,
                        exploitability_rationale=rationale,
                        remediation=f"Configure the web server or application to include the '{header}' header in all responses.",
                        owasp_category="A05:2021 – Security Misconfiguration",
                        cwe_id=cwe_id
                    ))
            
            # Acknowledge correctly configured headers (for logging/reporting)
            if present_headers:
                print(f"[API Agent] ✓ Security headers correctly configured: {', '.join(present_headers)}")
            
        except Exception as e:
            print(f"[API Agent] Header check error: {e}")
        
        return results
    
    async def _check_exposed_configs(self, target_url: str) -> List[AgentResult]:
        """
        Check for exposed configuration files.
        
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
            "/robots.txt",
            "/sitemap.xml",
        ]
        
        for path in config_files:
            url = urljoin(target_url, path)
            
            try:
                response = await self.make_request(url)
                
                if response and response.status_code == 200:
                    # Skip common non-sensitive files
                    if path in ["/robots.txt", "/sitemap.xml"]:
                        continue
                    
                    # Check if it contains sensitive data
                    has_sensitive = any(
                        kw in response.text.lower()
                        for kw in ["password", "secret", "api_key", "database", "private"]
                    )
                    
                    if has_sensitive:
                        results.append(self.create_result(
                            vulnerability_type=VulnerabilityType.INFO_DISCLOSURE,
                            is_vulnerable=True,
                            severity=Severity.HIGH,
                            confidence=90,
                            url=url,
                            title=f"Exposed Configuration File: {path}",
                            description=f"The configuration file {path} is publicly accessible and contains potentially sensitive information.",
                            evidence=f"File accessible: {path}",
                            remediation="Remove or restrict access to configuration files. Use web server rules to deny access to sensitive files.",
                            owasp_category="A05:2021 – Security Misconfiguration",
                            cwe_id="CWE-538"
                        ))
            
            except Exception as e:
                pass
        
        return results
    
    async def _test_cors(self, url: str) -> AgentResult | None:
        """
        Test for CORS misconfigurations.
        
        Args:
            url: URL to test
            
        Returns:
            AgentResult if vulnerable, None otherwise
        """
        try:
            # Test with arbitrary origin
            response = await self.make_request(
                url,
                headers={"Origin": "https://evil.example.com"}
            )
            
            if response is None:
                return None
            
            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")
            
            # Dangerous: reflecting arbitrary origin with credentials
            if acao == "https://evil.example.com" and acac.lower() == "true":
                return self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.HIGH,
                    confidence=95,
                    url=url,
                    title="Insecure CORS Configuration (Reflected Origin)",
                    description="The server reflects arbitrary origins in Access-Control-Allow-Origin header while allowing credentials. This allows any website to make authenticated requests to the API.",
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    likelihood=8.0,
                    impact=8.0,
                    exploitability_rationale="This configuration allows any malicious site to perform authenticated actions on behalf of a victim if they are logged into the target API. It is a direct path to cross-site request forgery and data theft.",
                    remediation="Do not reflect arbitrary origins. Whitelist only trusted origins. Never use 'Allow-Credentials: true' with 'Allow-Origin: *'.",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    cwe_id="CWE-942"
                )
            
            # Dangerous: wildcard origin with credentials (though many browsers block this combination)
            if acao == "*" and acac.lower() == "true":
                return self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.MEDIUM,
                    confidence=90,
                    url=url,
                    title="Overly Permissive CORS Policy (Wildcard + Credentials)",
                    description="The server uses wildcard (*) for Access-Control-Allow-Origin while allowing credentials, which is highly insecure and often disallowed by modern browsers.",
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    likelihood=4.0,
                    impact=7.0,
                    exploitability_rationale="While modern browsers prevent carrying credentials with a wildcard ACAO, this configuration indicates a lack of CORS understanding and may be exploitable in older clients or if the server logic has other flaws.",
                    remediation="Specify explicit allowed origins instead of using wildcards when credentials are required.",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    cwe_id="CWE-942"
                )
            
            # Informational: Wildcard without credentials (common and typically acceptable)
            if acao == "*" and acac.lower() != "true":
                return self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.INFO,
                    confidence=100,
                    url=url,
                    title="Permissive CORS Policy (Wildcard Origin)",
                    description="The server uses a wildcard (*) for Access-Control-Allow-Origin. This is acceptable for public APIs but should be reviewed if the endpoint handles sensitive data.",
                    evidence=f"ACAO: {acao}, ACAC: {acac or 'not set'}",
                    likelihood=1.0,
                    impact=2.0,
                    exploitability_rationale="Not directly exploitable. Wildcard CORS without credentials is a design choice suitable for public resources. Only a concern if sensitive, user-specific data is exposed.",
                    remediation="Verify this endpoint does not return sensitive user-specific data. If it does, implement an origin whitelist.",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    cwe_id="CWE-942"
                )
            
            # Informational: Origin reflected but no credentials (lower risk)
            if acao == "https://evil.example.com" and acac.lower() != "true":
                return self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.LOW,
                    confidence=85,
                    url=url,
                    title="CORS Origin Reflection Without Credentials",
                    description="The server reflects arbitrary origins in the Access-Control-Allow-Origin header but does not allow credentials. This is lower risk but indicates potential misconfiguration.",
                    evidence=f"ACAO: {acao}, ACAC: {acac or 'not set'}",
                    likelihood=3.0,
                    impact=3.0,
                    exploitability_rationale="Low exploitability. Without credentials, cross-origin requests cannot access authenticated user data. However, any publicly accessible data can be read by any website.",
                    remediation="Implement an origin whitelist instead of reflecting arbitrary origins. Ensure no sensitive data is accessible without authentication.",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    cwe_id="CWE-942"
                )
            
        except Exception as e:
            print(f"[API Agent] CORS test error: {e}")
        
        return None
