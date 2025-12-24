"""
API Security Agent - Tests REST API security.
"""
from typing import List, Dict, Any
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
    SECURITY_HEADERS = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-XSS-Protection",
        "Access-Control-Allow-Origin",
    ]
    
    async def scan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str] = None
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
        
        for path in self.API_PATHS:
            url = urljoin(target_url, path)
            
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
    
    async def _check_security_headers(self, url: str) -> List[AgentResult]:
        """
        Check for missing security headers.
        
        Args:
            url: URL to check
            
        Returns:
            List of security header issues
        """
        results = []
        
        try:
            response = await self.make_request(url)
            if response is None:
                return results
            
            headers = response.headers
            missing_headers = []
            
            for header in self.SECURITY_HEADERS:
                if header.lower() not in [h.lower() for h in headers.keys()]:
                    missing_headers.append(header)
            
            if missing_headers:
                results.append(self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.LOW,
                    confidence=95,
                    url=url,
                    title="Missing Security Headers",
                    description=f"The application is missing important security headers: {', '.join(missing_headers)}",
                    evidence=f"Missing headers: {missing_headers}",
                    remediation="Add security headers: X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Content-Security-Policy, Strict-Transport-Security (for HTTPS)",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    cwe_id="CWE-693"
                ))
            
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
                    title="Insecure CORS Configuration",
                    description="The server reflects arbitrary origins in Access-Control-Allow-Origin header while allowing credentials. This allows any website to make authenticated requests to the API.",
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    remediation="Do not reflect arbitrary origins. Whitelist only trusted origins. Never use 'Allow-Credentials: true' with 'Allow-Origin: *'.",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    cwe_id="CWE-942"
                )
            
            # Dangerous: wildcard origin
            if acao == "*" and acac.lower() == "true":
                return self.create_result(
                    vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                    is_vulnerable=True,
                    severity=Severity.MEDIUM,
                    confidence=90,
                    url=url,
                    title="Overly Permissive CORS Policy",
                    description="The server uses wildcard (*) for Access-Control-Allow-Origin, allowing any website to access the API.",
                    evidence=f"ACAO: {acao}",
                    remediation="Specify explicit allowed origins instead of using wildcards.",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    cwe_id="CWE-942"
                )
            
        except Exception as e:
            print(f"[API Agent] CORS test error: {e}")
        
        return None
